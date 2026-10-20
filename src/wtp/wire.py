# SPDX-License-Identifier: AGPL-3.0-only
"""RFC 8785 JCS / Strict JSON / Ed25519 Signed Envelope Implementation for Wutong Protocol v0.1.1.

Refinements in v0.1.1:
- Enforces RFC 8032 §5.1.7 / ZIP-215 canonical Ed25519 signature scalar bound `0 <= S < L`
  (`L = 2^252 + 27742317777372353535851937790883648493`) to eliminate signature malleability.
- Rejects all-zero and known small-order / torsion Ed25519 and X25519 public keys (`validate_ed25519_public_key_bytes`).
- Supports `proof.encoding` (`"jcs"` | `"dcbor"`) so envelopes signed in `dcbor` and later
  transcoded to JSON (or vice versa) verify against the original signing bytes without re-signing.
"""
import base64
import datetime as dt
import hashlib
import json
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PREFIX = b"WUTONG-SIG-V0.1\x00"
CBOR_PREFIX = b"WUTONG-CBOR-SIG-V0.1\x00"
ASCII_KEY = re.compile(r"^[\x21-\x7e]+$")
EXT_NS_RE = re.compile(r"^[a-z0-9]+(\.[a-z0-9_-]+)+$")
URN = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# Ed25519 base point order L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032 §5.1)
ED25519_L = (1 << 252) + 27742317777372353535851937790883648493

# Known small-order / low-order Curve25519 / Ed25519 32-byte encodings (RFC 7748 / ZIP-215)
SMALL_ORDER_PUBKEYS_HEX = {
    "00" * 32,
    "01" + "00" * 31,
    "00" * 31 + "80",
    "01" + "00" * 30 + "80",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
}


class WtpError(ValueError):
    pass


class ReplayError(WtpError):
    pass


class EquivocationError(WtpError):
    pass


def validate_public_key_hex(pubkey_hex: str) -> bytes:
    """Rejects malformed or known small-order / identity Ed25519 & X25519 public keys."""
    if not isinstance(pubkey_hex, str) or not re.fullmatch(r"^[0-9a-f]{64}$", pubkey_hex):
        raise WtpError("ERR_KEY_UNBOUND: public_key must be 64 lowercase hex characters")
    if pubkey_hex in SMALL_ORDER_PUBKEYS_HEX:
        raise WtpError("ERR_KEY_UNBOUND: weak or small-order public key rejected")
    return bytes.fromhex(pubkey_hex)


def check_ed25519_signature_canonical(signature: bytes) -> None:
    """Enforces RFC 8032 §5.1.7 / ZIP-215: 64-byte signature (R || S) must have 0 <= S < L."""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise WtpError("ERR_SIGNATURE: signature length must be 64 bytes")
    s_scalar = int.from_bytes(signature[32:64], "little")
    if s_scalar >= ED25519_L:
        raise WtpError("ERR_SIGNATURE: non-canonical Ed25519 scalar S >= L rejected")


def _utf16_code_unit_key(s: str) -> bytes:
    """RFC 8785 §3.2.3: sort object member names by UTF-16 code units (big-endian)."""
    return s.encode("utf-16-be")


def check_critical_extensions(message: dict, *, supported_extensions=()) -> bool:
    if "critical" not in message:
        return True
    crit = message["critical"]
    if not isinstance(crit, list) or not crit or len(crit) != len(set(crit)):
        raise WtpError("ERR_SCHEMA: invalid critical extensions array")
    ext_obj = message.get("extensions")
    payload_x = (
        message.get("payload", {}).get("x")
        if isinstance(message.get("payload"), dict)
        else None
    )
    present_keys = set()
    if isinstance(ext_obj, dict):
        present_keys.update(ext_obj.keys())
    if isinstance(payload_x, dict):
        present_keys.update(payload_x.keys())
    supported_set = set(supported_extensions)
    for ns in crit:
        if not isinstance(ns, str) or not EXT_NS_RE.fullmatch(ns):
            raise WtpError(f"ERR_SCHEMA: invalid critical extension namespace {ns!r}")
        if ns not in present_keys:
            raise WtpError(
                f"ERR_SCHEMA: critical extension {ns!r} not present in extensions"
            )
        if ns not in supported_set:
            raise WtpError(
                f"ERR_VERSION: unsupported critical extension {ns!r}"
            )
    return True


def strict_loads(raw, *, max_size=1_048_576, allow_unicode_keys=False):
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "strict")
    if len(raw) > max_size:
        raise WtpError("ERR_SCHEMA: size exceeded")
    try:
        def unique(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise WtpError("ERR_SCHEMA: duplicate key")
                d[k] = v
            return d

        obj = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                WtpError("ERR_SCHEMA: non-finite number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, UnicodeEncodeError) as e:
        raise WtpError(f"ERR_SCHEMA: {e}") from e
    validate_jcs_subset(obj, allow_unicode_keys=allow_unicode_keys)
    return obj


def validate_jcs_subset(o, depth=0, *, allow_unicode_keys=False):
    if depth > 40:
        raise WtpError("ERR_SCHEMA: nesting limit")
    if o is None or isinstance(o, bool):
        return
    if isinstance(o, int) and not isinstance(o, bool):
        if not (-(2**53) + 1 <= o <= 2**53 - 1):
            raise WtpError("ERR_SCHEMA: unsafe integer")
        return
    if isinstance(o, float):
        raise WtpError(
            "ERR_SCHEMA: floating numbers not supported by wtp/0.1 JSON profile"
        )
    if isinstance(o, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in o):
            raise WtpError("ERR_SCHEMA: unpaired surrogate")
        return
    if isinstance(o, list):
        for x in o:
            validate_jcs_subset(x, depth + 1, allow_unicode_keys=allow_unicode_keys)
        return
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise WtpError("ERR_SCHEMA: non-string member name")
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in k):
                raise WtpError("ERR_SCHEMA: unpaired surrogate in key")
            if not allow_unicode_keys and not ASCII_KEY.fullmatch(k):
                raise WtpError("ERR_SCHEMA: non-ASCII member name")
            validate_jcs_subset(v, depth + 1, allow_unicode_keys=allow_unicode_keys)
        return
    raise WtpError("ERR_SCHEMA: unsupported JSON value")


def _serialize_jcs_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False, allow_nan=False)


def _serialize_jcs_node(o) -> str:
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, int):
        return str(o)
    if isinstance(o, str):
        return _serialize_jcs_str(o)
    if isinstance(o, list):
        return "[" + ",".join(_serialize_jcs_node(x) for x in o) + "]"
    if isinstance(o, dict):
        sorted_keys = sorted(o.keys(), key=_utf16_code_unit_key)
        return (
            "{"
            + ",".join(
                f"{_serialize_jcs_str(k)}:{_serialize_jcs_node(o[k])}"
                for k in sorted_keys
            )
            + "}"
        )
    raise WtpError("ERR_SCHEMA: unsupported JSON value")


def canonical_bytes(obj, *, allow_unicode_keys=False) -> bytes:
    validate_jcs_subset(obj, allow_unicode_keys=allow_unicode_keys)
    return _serialize_jcs_node(obj).encode("utf-8")


def canonical_sha256(obj, *, allow_unicode_keys=False) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_bytes(obj, allow_unicode_keys=allow_unicode_keys)
    ).hexdigest()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def deb64u(text: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch("[A-Za-z0-9_-]+", text):
        raise WtpError("ERR_SIGNATURE: bad base64url")
    b = base64.urlsafe_b64decode(text + "=" * ((-len(text)) % 4))
    if b64u(b) != text:
        raise WtpError("ERR_SIGNATURE: noncanonical base64url")
    return b


def parse_time(ts: str) -> dt.datetime:
    if not isinstance(ts, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ts
    ):
        raise WtpError("ERR_SCHEMA: expected UTC second-resolution RFC3339 timestamp")
    try:
        return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as e:
        raise WtpError("ERR_SCHEMA: invalid timestamp") from e


def sign_envelope(
    message,
    private_seed,
    *,
    signer_id,
    key_id,
    issued_at,
    nonce,
    include_encoding=False,
):
    if "proof" in message or "auth" in message:
        raise WtpError("ERR_SIGNATURE: already has auth/proof")
    if not URN.fullmatch(signer_id):
        raise WtpError("ERR_SIGNATURE: invalid signer")
    if not isinstance(private_seed, bytes) or len(private_seed) != 32:
        raise WtpError("ERR_SIGNATURE: bad seed")
    parse_time(issued_at)
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        raise WtpError("ERR_SIGNATURE: bad nonce")
    out = dict(message)
    out["auth"] = {
        "signer_id": signer_id,
        "key_id": key_id,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    signature = Ed25519PrivateKey.from_private_bytes(private_seed).sign(
        PREFIX + canonical_bytes(out)
    )
    check_ed25519_signature_canonical(signature)
    proof_obj = {"alg": "Ed25519", "sig": b64u(signature)}
    if include_encoding:
        proof_obj["encoding"] = "jcs"
    out["proof"] = proof_obj
    return out


def verify_envelope(
    message,
    lookup_public_key,
    *,
    now=None,
    replay=None,
    max_clock_skew_seconds=300,
    mode="live",
    purpose="signing",
    supported_extensions=(),
):
    """Verifies a signed WTP envelope (supporting both native JCS and transcoded dCBOR proofs)."""
    if (
        not isinstance(message, dict)
        or not isinstance(message.get("auth"), dict)
        or not isinstance(message.get("proof"), dict)
    ):
        raise WtpError("ERR_SIGNATURE: missing auth or proof")
    check_critical_extensions(message, supported_extensions=supported_extensions)
    auth = message["auth"]
    proof = message["proof"]
    allowed_proof_keys = {"alg", "sig", "encoding"}
    if (
        set(auth) != {"signer_id", "key_id", "issued_at", "nonce"}
        or not {"alg", "sig"}.issubset(set(proof))
        or not set(proof).issubset(allowed_proof_keys)
        or proof["alg"] != "Ed25519"
    ):
        raise WtpError("ERR_SIGNATURE: invalid proof shape")
    enc_mode = proof.get("encoding", "jcs")
    if enc_mode not in ("jcs", "dcbor"):
        raise WtpError("ERR_SIGNATURE: unsupported proof.encoding")
    if not URN.fullmatch(auth["signer_id"]):
        raise WtpError("ERR_SIGNATURE: bad signer")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", auth["nonce"]):
        raise WtpError("ERR_SIGNATURE: bad nonce")
    when = parse_time(auth["issued_at"])
    signed = {k: v for k, v in message.items() if k != "proof"}
    if enc_mode == "dcbor":
        from .cbor_wire import dcbor_dumps

        signed_bytes = dcbor_dumps(signed)
        sig_input = CBOR_PREFIX + signed_bytes
    else:
        signed_bytes = canonical_bytes(signed)
        sig_input = PREFIX + signed_bytes

    digest = "sha256:" + hashlib.sha256(signed_bytes).hexdigest()
    signature = deb64u(proof["sig"])
    check_ed25519_signature_canonical(signature)

    try:
        pub = lookup_public_key(
            auth["signer_id"],
            auth["key_id"],
            at_time=auth["issued_at"],
            purpose=purpose,
        )
    except TypeError:
        pub = lookup_public_key(auth["signer_id"], auth["key_id"])
    if pub is None:
        raise WtpError("ERR_KEY_UNBOUND: unknown authenticated key")
    try:
        pub.verify(signature, sig_input)
    except Exception as e:
        raise WtpError("ERR_SIGNATURE: signature mismatch") from e

    if mode == "live":
        now = now or dt.datetime.now(dt.timezone.utc)
        if abs((now - when).total_seconds()) > max_clock_skew_seconds:
            raise WtpError("ERR_SIGNATURE: timestamp outside live replay window")
        if replay is not None:
            replay.consume(
                auth["signer_id"],
                auth["nonce"],
                message["id"],
                canonical_digest=digest,
                issued_at=auth["issued_at"],
            )
    elif mode == "archive":
        if replay is not None and hasattr(replay, "check_equivocation"):
            replay.check_equivocation(
                auth["signer_id"], message["id"], canonical_digest=digest
            )
    else:
        raise WtpError(f"ERR_UNSUPPORTED: unknown verification mode {mode!r}")
    return True


class ReplayCache:
    """In-memory replay & equivocation cache for lightweight unit tests."""

    def __init__(self):
        self.seen_nonces = {}
        self.seen_messages = {}

    def check_equivocation(self, principal, message_id, *, canonical_digest=None):
        if canonical_digest is not None and message_id in self.seen_messages:
            prev_signer, prev_digest = self.seen_messages[message_id]
            if prev_digest != canonical_digest or prev_signer != principal:
                raise EquivocationError("ERR_EQUIVOCATION: signed message ID fork")

    def consume(
        self,
        principal,
        nonce,
        message_id,
        *,
        canonical_digest=None,
        issued_at=None,
    ):
        self.check_equivocation(
            principal, message_id, canonical_digest=canonical_digest
        )
        k = (principal, nonce)
        if k in self.seen_nonces:
            raise ReplayError("ERR_REPLAY: replayed nonce")
        self.seen_nonces[k] = (message_id, canonical_digest)
        if canonical_digest is not None:
            self.seen_messages[message_id] = (principal, canonical_digest)
