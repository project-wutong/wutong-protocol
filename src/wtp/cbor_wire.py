# SPDX-License-Identifier: AGPL-3.0-only
"""RFC 8949 §4.2.1 Core Deterministic CBOR (dCBOR) Wire Encoder, Decoder, and Ed25519 Signer/Verifier (v0.1.1).

Refinements in v0.1.1:
- Enforces 1-to-1 bijection with WTP JSON (`allow_raw_bytes=False` by default so Major Type 2
  byte strings are rejected in wire envelopes in favor of canonical Base64URL text strings).
- Enforces RFC 8032 §5.1.7 / ZIP-215 canonical Ed25519 signature scalar bound `0 <= S < L`.
- Supports `include_encoding=True` (`proof.encoding = "dcbor"`) so CBOR-signed envelopes
  transcoded to JSON by Federation Gateways remain cryptographically verifiable via `verify_envelope`.
"""
import datetime as dt
import hashlib
import re
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .wire import (
    ASCII_KEY,
    CBOR_PREFIX,
    PREFIX,
    URN,
    WtpError,
    b64u,
    canonical_bytes,
    check_critical_extensions,
    check_ed25519_signature_canonical,
    deb64u,
    parse_time,
    validate_jcs_subset,
)


def _encode_head(major: int, arg: int) -> bytes:
    mt = major << 5
    if arg < 24:
        return bytes([mt | arg])
    if arg <= 0xFF:
        return bytes([mt | 24, arg])
    if arg <= 0xFFFF:
        return struct.pack(">BH", mt | 25, arg)
    if arg <= 0xFFFFFFFF:
        return struct.pack(">BI", mt | 26, arg)
    if arg <= 0xFFFFFFFFFFFFFFFF:
        return struct.pack(">BQ", mt | 27, arg)
    raise WtpError("ERR_SCHEMA: CBOR integer argument overflow")


def _encode_dcbor_item(o, depth: int = 0) -> bytes:
    if depth > 40:
        raise WtpError("ERR_SCHEMA: CBOR nesting limit")
    if o is None:
        return b"\xf6"
    if o is False:
        return b"\xf4"
    if o is True:
        return b"\xf5"
    if isinstance(o, int) and not isinstance(o, bool):
        if not (-(2**53) + 1 <= o <= 2**53 - 1):
            raise WtpError("ERR_SCHEMA: unsafe integer for WTP CBOR profile")
        if o >= 0:
            return _encode_head(0, o)
        return _encode_head(1, -1 - o)
    if isinstance(o, str):
        raw = o.encode("utf-8", "strict")
        return _encode_head(3, len(raw)) + raw
    if isinstance(o, list):
        out = [_encode_head(4, len(o))]
        for x in o:
            out.append(_encode_dcbor_item(x, depth + 1))
        return b"".join(out)
    if isinstance(o, dict):
        encoded_pairs = []
        for k, v in o.items():
            if not isinstance(k, str):
                raise WtpError("ERR_SCHEMA: CBOR map key must be text string")
            ek = _encode_dcbor_item(k, depth + 1)
            ev = _encode_dcbor_item(v, depth + 1)
            encoded_pairs.append((ek, ev))
        encoded_pairs.sort(key=lambda pair: pair[0])
        out = [_encode_head(5, len(encoded_pairs))]
        for ek, ev in encoded_pairs:
            out.append(ek)
            out.append(ev)
        return b"".join(out)
    raise WtpError("ERR_SCHEMA: unsupported value for dCBOR (raw bytes forbidden; use base64url)")


def dcbor_dumps(obj, *, allow_unicode_keys: bool = False) -> bytes:
    validate_jcs_subset(obj, allow_unicode_keys=allow_unicode_keys)
    return _encode_dcbor_item(obj, 0)


def _decode_head(buf: memoryview, pos: int):
    if pos >= len(buf):
        raise WtpError("ERR_SCHEMA: truncated CBOR input")
    initial = buf[pos]
    major = initial >> 5
    ai = initial & 0x1F
    pos += 1
    if ai < 24:
        return major, ai, pos
    if ai == 24:
        if pos + 1 > len(buf):
            raise WtpError("ERR_SCHEMA: truncated CBOR 1-byte arg")
        val = buf[pos]
        if val < 24:
            raise WtpError("ERR_SCHEMA: non-minimal 1-byte CBOR integer encoding")
        return major, val, pos + 1
    if ai == 25:
        if pos + 2 > len(buf):
            raise WtpError("ERR_SCHEMA: truncated CBOR 2-byte arg")
        val = struct.unpack_from(">H", buf, pos)[0]
        if val <= 0xFF:
            raise WtpError("ERR_SCHEMA: non-minimal 2-byte CBOR integer encoding")
        return major, val, pos + 2
    if ai == 26:
        if pos + 4 > len(buf):
            raise WtpError("ERR_SCHEMA: truncated CBOR 4-byte arg")
        val = struct.unpack_from(">I", buf, pos)[0]
        if val <= 0xFFFF:
            raise WtpError("ERR_SCHEMA: non-minimal 4-byte CBOR integer encoding")
        return major, val, pos + 4
    if ai == 27:
        if pos + 8 > len(buf):
            raise WtpError("ERR_SCHEMA: truncated CBOR 8-byte arg")
        val = struct.unpack_from(">Q", buf, pos)[0]
        if val <= 0xFFFFFFFF:
            raise WtpError("ERR_SCHEMA: non-minimal 8-byte CBOR integer encoding")
        return major, val, pos + 8
    if ai == 31:
        raise WtpError("ERR_SCHEMA: indefinite-length CBOR forbidden in dCBOR")
    raise WtpError("ERR_SCHEMA: reserved/floating CBOR additional info rejected")


def _decode_dcbor_item(buf: memoryview, pos: int, depth: int, allow_unicode_keys: bool):
    if depth > 40:
        raise WtpError("ERR_SCHEMA: CBOR nesting limit")
    major, arg, pos = _decode_head(buf, pos)
    if major == 0:
        if arg > 2**53 - 1:
            raise WtpError("ERR_SCHEMA: CBOR unsigned int exceeds safe range")
        return arg, pos
    if major == 1:
        val = -1 - arg
        if val < -(2**53) + 1:
            raise WtpError("ERR_SCHEMA: CBOR negative int exceeds safe range")
        return val, pos
    if major == 2:
        raise WtpError("ERR_SCHEMA: raw CBOR byte strings forbidden in WTP wire profile; use base64url")
    if major == 3:
        if pos + arg > len(buf):
            raise WtpError("ERR_SCHEMA: truncated CBOR text string")
        try:
            s = bytes(buf[pos : pos + arg]).decode("utf-8", "strict")
        except UnicodeDecodeError as e:
            raise WtpError("ERR_SCHEMA: invalid UTF-8 in CBOR text string") from e
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in s):
            raise WtpError("ERR_SCHEMA: unpaired surrogate in CBOR text string")
        return s, pos + arg
    if major == 4:
        arr = []
        for _ in range(arg):
            item, pos = _decode_dcbor_item(buf, pos, depth + 1, allow_unicode_keys)
            arr.append(item)
        return arr, pos
    if major == 5:
        obj = {}
        prev_key_bytes = None
        for _ in range(arg):
            key_start = pos
            k_major = buf[pos] >> 5 if pos < len(buf) else -1
            if k_major != 3:
                raise WtpError("ERR_SCHEMA: CBOR map key must be text string")
            k, pos = _decode_dcbor_item(buf, pos, depth + 1, allow_unicode_keys)
            key_bytes = bytes(buf[key_start:pos])
            if not allow_unicode_keys and not ASCII_KEY.fullmatch(k):
                raise WtpError("ERR_SCHEMA: non-ASCII member name in CBOR map")
            if prev_key_bytes is not None:
                if key_bytes == prev_key_bytes:
                    raise WtpError("ERR_SCHEMA: duplicate CBOR map key")
                if key_bytes < prev_key_bytes:
                    raise WtpError("ERR_SCHEMA: unsorted CBOR map keys violate RFC 8949 §4.2.1")
            prev_key_bytes = key_bytes
            v, pos = _decode_dcbor_item(buf, pos, depth + 1, allow_unicode_keys)
            obj[k] = v
        return obj, pos
    if major == 7:
        if arg == 20:
            return False, pos
        if arg == 21:
            return True, pos
        if arg == 22:
            return None, pos
        raise WtpError("ERR_SCHEMA: unsupported CBOR simple value or float")
    raise WtpError("ERR_SCHEMA: unsupported CBOR major type")


def dcbor_loads(raw: bytes, *, max_size: int = 1_048_576, allow_unicode_keys: bool = False):
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise WtpError("ERR_SCHEMA: CBOR input must be bytes")
    if len(raw) > max_size:
        raise WtpError("ERR_SCHEMA: CBOR size exceeded")
    buf = memoryview(raw)
    val, pos = _decode_dcbor_item(buf, 0, 0, allow_unicode_keys)
    if pos != len(buf):
        raise WtpError("ERR_SCHEMA: trailing bytes after CBOR root")
    return val


def sign_cbor_envelope(
    message: dict,
    private_seed: bytes,
    *,
    signer_id: str,
    key_id: str,
    issued_at: str,
    nonce: str,
    include_encoding: bool = False,
) -> bytes:
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
    signing_bytes = CBOR_PREFIX + dcbor_dumps(out)
    sig = Ed25519PrivateKey.from_private_bytes(private_seed).sign(signing_bytes)
    check_ed25519_signature_canonical(sig)
    proof_obj = {"alg": "Ed25519", "sig": b64u(sig)}
    if include_encoding:
        proof_obj["encoding"] = "dcbor"
    out["proof"] = proof_obj
    return dcbor_dumps(out)


def verify_cbor_envelope(
    raw_cbor: bytes,
    lookup_public_key,
    *,
    now=None,
    replay=None,
    max_clock_skew_seconds: int = 300,
    mode: str = "live",
    purpose: str = "signing",
    supported_extensions=(),
) -> dict:
    message = dcbor_loads(raw_cbor)
    if (
        not isinstance(message, dict)
        or not isinstance(message.get("auth"), dict)
        or not isinstance(message.get("proof"), dict)
    ):
        raise WtpError("ERR_SIGNATURE: missing auth or proof in CBOR envelope")
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
    enc_mode = proof.get("encoding", "dcbor")
    if enc_mode not in ("jcs", "dcbor"):
        raise WtpError("ERR_SIGNATURE: unsupported proof.encoding")
    if not URN.fullmatch(auth["signer_id"]):
        raise WtpError("ERR_SIGNATURE: bad signer")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", auth["nonce"]):
        raise WtpError("ERR_SIGNATURE: bad nonce")
    when = parse_time(auth["issued_at"])
    signed = {k: v for k, v in message.items() if k != "proof"}
    if enc_mode == "jcs":
        signed_bytes = canonical_bytes(signed)
        sig_input = PREFIX + signed_bytes
    else:
        signed_bytes = dcbor_dumps(signed)
        sig_input = CBOR_PREFIX + signed_bytes

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
        raise WtpError("ERR_SIGNATURE: CBOR signature mismatch") from e

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
    return message
