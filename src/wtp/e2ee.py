# SPDX-License-Identifier: AGPL-3.0-only
"""WTP-Security Space End-to-End Encryption (E2EE) & Multi-Member Epoch Key Wrapping (`wutong.encrypted_envelope` & `wutong.space_epoch`).

Refinements in v0.1.1:
1. Adds `create_space_epoch_envelope` and `unwrap_space_epoch_for_member` (`wutong.space_epoch`):
   - Wraps the 64-byte Space Epoch key material (`epoch_secret (32B) || space_x25519_priv (32B)`)
     individually to each authorized member's bound X25519 public key (`alg="X25519"`, `purpose="encryption"`
     in `KeyRegistry`) using X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305.
   - When a member is removed in `epoch + 1`, their `member_id` is omitted from `member_wraps`, so
     they cannot unwrap the `epoch + 1` key bundle or decrypt any `epoch + 1` `wutong.encrypted_envelope`.
2. Rejects weak/small-order X25519 public keys and all-zero ECDH shared secrets per RFC 7748 §6.1.
"""
import hashlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .wire import (
    WtpError,
    b64u,
    canonical_bytes,
    deb64u,
    sign_envelope,
    strict_loads,
    validate_public_key_hex,
    verify_envelope,
)


class DecryptionError(WtpError):
    pass


def _safe_x25519_exchange(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
    shared = priv.exchange(pub)
    if shared == b"\x00" * 32:
        raise DecryptionError("ERR_DECRYPTION_FAILED: all-zero X25519 shared secret rejected per RFC 7748 §6.1")
    return shared


class SpaceEpochKeyring:
    """Manages per-Space epoch secrets and X25519 Space keypairs for E2EE spaces."""

    def __init__(self, space_id: str):
        self.space_id = space_id
        self.current_epoch = 0
        self.epochs = {}

    def advance_epoch(
        self,
        *,
        epoch_secret: bytes = None,
        x25519_seed: bytes = None,
        key_id: str = None,
    ) -> dict:
        self.current_epoch += 1
        ep = self.current_epoch
        secret = epoch_secret if epoch_secret is not None else os.urandom(32)
        if len(secret) != 32:
            raise WtpError("ERR_SCHEMA: epoch_secret must be 32 bytes")
        raw_x_seed = x25519_seed if x25519_seed is not None else os.urandom(32)
        priv = X25519PrivateKey.from_private_bytes(raw_x_seed)
        pub_hex = (
            priv.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
        validate_public_key_hex(pub_hex)
        kid = key_id or f"space-epoch-{ep:04d}"
        rec = {
            "epoch": ep,
            "key_id": kid,
            "epoch_secret": secret,
            "x25519_seed": raw_x_seed,
            "x25519_priv": priv,
            "x25519_pub_hex": pub_hex,
        }
        self.epochs[ep] = rec
        return rec

    def install_unwrapped_epoch(
        self,
        *,
        epoch: int,
        key_id: str,
        epoch_secret: bytes,
        x25519_seed: bytes,
        expected_space_pub_hex: str = None,
    ) -> dict:
        priv = X25519PrivateKey.from_private_bytes(x25519_seed)
        pub_hex = (
            priv.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
        if expected_space_pub_hex is not None and pub_hex != expected_space_pub_hex:
            raise DecryptionError("ERR_DECRYPTION_FAILED: unwrapped space_x25519_pub mismatch")
        rec = {
            "epoch": epoch,
            "key_id": key_id,
            "epoch_secret": epoch_secret,
            "x25519_seed": x25519_seed,
            "x25519_priv": priv,
            "x25519_pub_hex": pub_hex,
        }
        self.epochs[epoch] = rec
        if epoch > self.current_epoch:
            self.current_epoch = epoch
        return rec

    def get_epoch(self, epoch: int) -> dict:
        if epoch not in self.epochs:
            raise DecryptionError(f"ERR_DECRYPTION_FAILED: unknown or revoked space epoch {epoch}")
        return self.epochs[epoch]


def create_space_epoch_envelope(
    keyring: SpaceEpochKeyring,
    *,
    epoch: int = None,
    envelope_id: str,
    epoch_id: str,
    occurred_at: str,
    issuer_id: str,
    issuer_key_id: str,
    issuer_seed: bytes,
    members: list,
    registry,
    outer_nonce: str,
    ephemeral_seed: bytes = None,
) -> dict:
    """Creates a signed `wutong.space_epoch` envelope wrapping the target epoch's
    64-byte bundle (`epoch_secret || x25519_seed`) to each authorized member's bound X25519 key.
    `members` is a list of `(member_principal_id, member_x25519_key_id)` pairs.
    """
    target_epoch = epoch if epoch is not None else keyring.current_epoch
    ep_rec = keyring.get_epoch(target_epoch)
    eph_priv = (
        X25519PrivateKey.from_private_bytes(ephemeral_seed)
        if ephemeral_seed is not None
        else X25519PrivateKey.generate()
    )
    eph_pub_hex = (
        eph_priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    bundle = ep_rec["epoch_secret"] + ep_rec["x25519_seed"]
    wraps = []
    for idx, (member_id, member_key_id) in enumerate(members):
        member_pub = registry.lookup_key(
            member_id, member_key_id, at_time=occurred_at, purpose="encryption"
        )
        if member_pub is None or not isinstance(member_pub, X25519PublicKey):
            raise WtpError(
                f"ERR_KEY_UNBOUND: member {member_id} missing valid X25519 encryption key {member_key_id}"
            )
        shared = _safe_x25519_exchange(eph_priv, member_pub)
        aad = f"WUTONG-EPOCH-WRAP-V0.1|{keyring.space_id}|{target_epoch}|{ep_rec['key_id']}|{member_id}|{member_key_id}".encode(
            "utf-8"
        )
        wrap_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=aad,
        ).derive(shared)
        nonce12 = hashlib.sha256(aad + str(idx).encode()).digest()[:12]
        ct = ChaCha20Poly1305(wrap_key).encrypt(nonce12, bundle, aad)
        wraps.append(
            {
                "member_id": member_id,
                "member_key_id": member_key_id,
                "nonce_b64u": b64u(nonce12),
                "wrapped_key_b64u": b64u(ct),
            }
        )

    unsigned = {
        "protocol": "wutong/0.1",
        "kind": "wutong.space_epoch",
        "id": envelope_id,
        "occurred_at": occurred_at,
        "payload": {
            "epoch_id": epoch_id,
            "space_id": keyring.space_id,
            "epoch": target_epoch,
            "key_id": ep_rec["key_id"],
            "issuer_id": issuer_id,
            "sender_ephemeral_pub": eph_pub_hex,
            "space_x25519_pub": ep_rec["x25519_pub_hex"],
            "member_wraps": wraps,
        },
    }
    return sign_envelope(
        unsigned,
        issuer_seed,
        signer_id=issuer_id,
        key_id=issuer_key_id,
        issued_at=occurred_at,
        nonce=outer_nonce,
    )


def unwrap_space_epoch_for_member(
    signed_epoch_envelope: dict,
    *,
    member_id: str,
    member_key_id: str,
    member_x25519_seed: bytes,
    target_keyring: SpaceEpochKeyring,
    lookup_public_key,
    now=None,
) -> dict:
    """Verifies outer signature on `wutong.space_epoch`, unwraps the member's entry,
    and installs the epoch keys into `target_keyring`.
    """
    if signed_epoch_envelope.get("kind") != "wutong.space_epoch":
        raise WtpError("ERR_SCHEMA: expected wutong.space_epoch")
    verify_envelope(signed_epoch_envelope, lookup_public_key, now=now, mode="archive")
    p = signed_epoch_envelope["payload"]
    if signed_epoch_envelope["auth"]["signer_id"] != p["issuer_id"]:
        raise WtpError("ERR_SIGNATURE: space_epoch signer must match issuer_id")
    if p["space_id"] != target_keyring.space_id:
        raise DecryptionError("ERR_DECRYPTION_FAILED: space_id mismatch")

    validate_public_key_hex(p["sender_ephemeral_pub"])
    sender_eph_pub = X25519PublicKey.from_public_bytes(
        bytes.fromhex(p["sender_ephemeral_pub"])
    )
    member_priv = X25519PrivateKey.from_private_bytes(member_x25519_seed)

    for entry in p["member_wraps"]:
        if entry["member_id"] == member_id and entry["member_key_id"] == member_key_id:
            shared = _safe_x25519_exchange(member_priv, sender_eph_pub)
            aad = f"WUTONG-EPOCH-WRAP-V0.1|{p['space_id']}|{p['epoch']}|{p['key_id']}|{member_id}|{member_key_id}".encode(
                "utf-8"
            )
            wrap_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=hashlib.sha256(aad).digest(),
                info=aad,
            ).derive(shared)
            try:
                bundle = ChaCha20Poly1305(wrap_key).decrypt(
                    deb64u(entry["nonce_b64u"]),
                    deb64u(entry["wrapped_key_b64u"]),
                    aad,
                )
            except Exception as e:
                raise DecryptionError("ERR_DECRYPTION_FAILED: failed to unwrap space_epoch key") from e
            if len(bundle) != 64:
                raise DecryptionError("ERR_DECRYPTION_FAILED: invalid unwrapped epoch bundle length")
            return target_keyring.install_unwrapped_epoch(
                epoch=p["epoch"],
                key_id=p["key_id"],
                epoch_secret=bundle[:32],
                x25519_seed=bundle[32:64],
                expected_space_pub_hex=p["space_x25519_pub"],
            )
    raise DecryptionError(f"ERR_DECRYPTION_FAILED: member {member_id} not authorized in space_epoch {p['epoch']}")


def _derive_aead_key(
    *,
    epoch_secret: bytes,
    shared_ecdh: bytes,
    space_id: str,
    epoch: int,
    key_id: str,
    inner_kind: str,
    aad_digest: str,
) -> bytes:
    info = (
        f"WUTONG-E2EE-V0.1|{space_id}|{epoch}|{key_id}|{inner_kind}|{aad_digest}"
    ).encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=epoch_secret,
        info=info,
    )
    return hkdf.derive(shared_ecdh)


def seal_encrypted_envelope(
    inner_signed_envelope: dict,
    *,
    envelope_id: str,
    occurred_at: str,
    keyring: SpaceEpochKeyring,
    epoch: int = None,
    signer_seed: bytes,
    signer_id: str,
    signer_key_id: str,
    issued_at: str,
    outer_nonce: str,
    aead_nonce: bytes = None,
    ephemeral_seed: bytes = None,
) -> dict:
    if "auth" not in inner_signed_envelope or "proof" not in inner_signed_envelope:
        raise WtpError("ERR_SIGNATURE: inner envelope must be signed before E2EE sealing")
    target_epoch = epoch if epoch is not None else keyring.current_epoch
    ep_rec = keyring.get_epoch(target_epoch)

    eph_priv = (
        X25519PrivateKey.from_private_bytes(ephemeral_seed)
        if ephemeral_seed is not None
        else X25519PrivateKey.generate()
    )
    eph_pub_hex = (
        eph_priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    validate_public_key_hex(eph_pub_hex)
    recipient_pub = X25519PublicKey.from_public_bytes(
        bytes.fromhex(ep_rec["x25519_pub_hex"])
    )
    shared_ecdh = _safe_x25519_exchange(eph_priv, recipient_pub)

    inner_kind = inner_signed_envelope["kind"]
    aad_bytes = f"{keyring.space_id}|{target_epoch}|{ep_rec['key_id']}|{inner_kind}|{eph_pub_hex}".encode(
        "utf-8"
    )
    aad_digest = "sha256:" + hashlib.sha256(aad_bytes).hexdigest()

    aead_key = _derive_aead_key(
        epoch_secret=ep_rec["epoch_secret"],
        shared_ecdh=shared_ecdh,
        space_id=keyring.space_id,
        epoch=target_epoch,
        key_id=ep_rec["key_id"],
        inner_kind=inner_kind,
        aad_digest=aad_digest,
    )
    nonce12 = aead_nonce if aead_nonce is not None else os.urandom(12)
    if len(nonce12) != 12:
        raise WtpError("ERR_SCHEMA: ChaCha20-Poly1305 nonce must be 12 bytes")

    plaintext = canonical_bytes(inner_signed_envelope)
    ciphertext = ChaCha20Poly1305(aead_key).encrypt(nonce12, plaintext, aad_bytes)

    outer_unsigned = {
        "protocol": "wutong/0.1",
        "kind": "wutong.encrypted_envelope",
        "id": envelope_id,
        "occurred_at": occurred_at,
        "payload": {
            "space_id": keyring.space_id,
            "epoch": target_epoch,
            "key_id": ep_rec["key_id"],
            "sender_ephemeral_pub": eph_pub_hex,
            "aead_alg": "ChaCha20-Poly1305",
            "kdf_alg": "HKDF-SHA256",
            "nonce_b64u": b64u(nonce12),
            "inner_kind": inner_kind,
            "aad_digest": aad_digest,
            "ciphertext_b64u": b64u(ciphertext),
        },
    }
    return sign_envelope(
        outer_unsigned,
        signer_seed,
        signer_id=signer_id,
        key_id=signer_key_id,
        issued_at=issued_at,
        nonce=outer_nonce,
    )


def open_encrypted_envelope(
    outer_envelope: dict,
    *,
    keyring: SpaceEpochKeyring,
    lookup_public_key,
    now=None,
    replay=None,
    mode: str = "live",
) -> dict:
    if outer_envelope.get("kind") != "wutong.encrypted_envelope":
        raise WtpError("ERR_SCHEMA: expected wutong.encrypted_envelope")
    verify_envelope(
        outer_envelope,
        lookup_public_key,
        now=now,
        replay=replay,
        mode=mode,
    )
    p = outer_envelope["payload"]
    if p["space_id"] != keyring.space_id:
        raise DecryptionError("ERR_DECRYPTION_FAILED: space_id mismatch")
    ep_rec = keyring.get_epoch(p["epoch"])
    if p["key_id"] != ep_rec["key_id"]:
        raise DecryptionError("ERR_DECRYPTION_FAILED: epoch key_id mismatch")

    validate_public_key_hex(p["sender_ephemeral_pub"])
    aad_bytes = f"{p['space_id']}|{p['epoch']}|{p['key_id']}|{p['inner_kind']}|{p['sender_ephemeral_pub']}".encode(
        "utf-8"
    )
    expected_aad_digest = "sha256:" + hashlib.sha256(aad_bytes).hexdigest()
    if p["aad_digest"] != expected_aad_digest:
        raise DecryptionError("ERR_DECRYPTION_FAILED: aad_digest mismatch")

    sender_eph_pub = X25519PublicKey.from_public_bytes(
        bytes.fromhex(p["sender_ephemeral_pub"])
    )
    shared_ecdh = _safe_x25519_exchange(ep_rec["x25519_priv"], sender_eph_pub)
    aead_key = _derive_aead_key(
        epoch_secret=ep_rec["epoch_secret"],
        shared_ecdh=shared_ecdh,
        space_id=p["space_id"],
        epoch=p["epoch"],
        key_id=p["key_id"],
        inner_kind=p["inner_kind"],
        aad_digest=p["aad_digest"],
    )
    nonce12 = deb64u(p["nonce_b64u"])
    ciphertext = deb64u(p["ciphertext_b64u"])
    try:
        plaintext = ChaCha20Poly1305(aead_key).decrypt(nonce12, ciphertext, aad_bytes)
    except Exception as e:
        raise DecryptionError("ERR_DECRYPTION_FAILED: ChaCha20-Poly1305 authentication failed") from e

    inner = strict_loads(plaintext)
    if inner.get("kind") != p["inner_kind"]:
        raise DecryptionError("ERR_DECRYPTION_FAILED: inner_kind spoofing detected")
    verify_envelope(inner, lookup_public_key, now=now, mode="archive")
    return inner
