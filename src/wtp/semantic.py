# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic semantic validator for all 24 Wutong Protocol v0.1.2 message kinds."""
import hashlib
from .document_patch import apply_source_patches, validate_provenance
from .federation import validate_federation_endpoint
from .wire import (
    WtpError,
    check_critical_extensions,
    deb64u,
    parse_time,
    validate_public_key_hex,
)

WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def validate_relative_path(raw):
    if (
        not isinstance(raw, str)
        or not raw
        or "\x00" in raw
        or "\\" in raw
        or raw.startswith("/")
    ):
        raise WtpError("ERR_SYMLINK_OR_TRAVERSAL: unsafe relative_path")
    parts = raw.split("/")
    if any(x in ("", ".", "..") for x in parts):
        raise WtpError(
            "ERR_SYMLINK_OR_TRAVERSAL: path traversal or noncanonical path"
        )
    for part in parts:
        if (
            part.endswith((" ", "."))
            or ":" in part
            or part.upper().split(".")[0] in WINDOWS_RESERVED
        ):
            raise WtpError("ERR_SYMLINK_OR_TRAVERSAL: non-portable path")
    return True


def validate_semantics(message, body=None, *, supported_extensions=()):
    if not isinstance(message, dict):
        raise WtpError("ERR_SCHEMA: message must be object")
    occ_dt = parse_time(message["occurred_at"])
    if "auth" in message and isinstance(message["auth"], dict) and "issued_at" in message["auth"]:
        iss_dt = parse_time(message["auth"]["issued_at"])
        # Prevent signing future-dated occurred_at events with an earlier expiring key (>300s ahead)
        if (occ_dt - iss_dt).total_seconds() > 300:
            raise WtpError("ERR_SIGNATURE: occurred_at cannot be in the future relative to auth.issued_at")
    check_critical_extensions(message, supported_extensions=supported_extensions)
    typ = message["kind"].split(".")[-1]
    p = message["payload"]
    if "provenance" in p:
        validate_provenance(p["provenance"])
    if typ == "object":
        if p.get("binding", {}).get("kind") == "file":
            validate_relative_path(p["binding"]["relative_path"])
        if body is not None:
            if (
                len(body) != p["byte_length"]
                or "sha256:" + hashlib.sha256(body).hexdigest()
                != p["content_digest"]
            ):
                raise WtpError("ERR_CONFLICT: file size/digest mismatch")
    if typ == "artifact" and body is not None:
        if (
            len(body) != p["byte_length"]
            or "sha256:" + hashlib.sha256(body).hexdigest()
            != p["content_digest"]
        ):
            raise WtpError("ERR_CONFLICT: artifact size/digest mismatch")
    if typ == "revision" and p["revision_id"] in p.get("parents", []):
        raise WtpError("ERR_SCHEMA: self parent revision")
    if typ == "proposal" and "patches" in p:
        prev_end = 0
        for patch in p["patches"]:
            if patch["start_byte"] < prev_end or patch["end_byte"] < patch["start_byte"]:
                raise WtpError("ERR_CONFLICT: overlapping or inverted proposal patches")
            prev_end = patch["end_byte"]
        if body is not None:
            apply_source_patches(
                body,
                p["patches"],
                expected_base_digest=p["base_digest"],
                expected_proposed_digest=p["proposed_digest"],
            )
    if typ == "event" and p["event_id"] in p.get("causes", []):
        raise WtpError("ERR_SCHEMA: self causal reference")
    if typ == "capability":
        if not parse_time(p["not_before"]) < parse_time(p["expires_at"]):
            raise WtpError("ERR_SCHEMA: invalid capability duration")
        if p["capability_id"] == p.get("parent_id"):
            raise WtpError("ERR_SCHEMA: self parent capability")
        if any("*" in a for a in p["actions"]):
            raise WtpError("ERR_PERMISSION: wildcard action undefined")
    if typ == "key_binding":
        validate_public_key_hex(p["public_key"])
        if not parse_time(p["valid_from"]) < parse_time(p["valid_until"]):
            raise WtpError("ERR_SCHEMA: invalid key_binding duration")
        if p.get("previous_key_id") == p["key_id"]:
            raise WtpError("ERR_SCHEMA: self previous_key_id in key_binding")
        if p["alg"] == "X25519" and set(p["purposes"]) != {"encryption"}:
            raise WtpError("ERR_SCHEMA: X25519 key_binding must have purposes=['encryption']")
        if p["alg"] == "Ed25519" and "encryption" in p["purposes"]:
            raise WtpError("ERR_SCHEMA: Ed25519 key_binding cannot have encryption purpose")
    if typ == "space_epoch":
        validate_public_key_hex(p["sender_ephemeral_pub"])
        validate_public_key_hex(p["space_x25519_pub"])
        seen_members = set()
        for w in p["member_wraps"]:
            mk = (w["member_id"], w["member_key_id"])
            if mk in seen_members:
                raise WtpError("ERR_SCHEMA: duplicate member wrap in space_epoch")
            seen_members.add(mk)
            if len(deb64u(w["nonce_b64u"])) != 12:
                raise WtpError("ERR_SCHEMA: invalid nonce_b64u in space_epoch member_wrap")
    if typ == "revocation":
        parse_time(p["revoked_at"])
        parse_time(p["effective_from"])
        if p["revocation_id"] == p["target_id"]:
            raise WtpError("ERR_SCHEMA: self revocation target")
    if typ == "service_invocation":
        if any("*" in p["action"] for _ in (0,)):
            raise WtpError("ERR_PERMISSION: wildcard action forbidden in service_invocation")
        if "auth" in message and message["auth"].get("signer_id") != p["caller_id"]:
            raise WtpError("ERR_PERMISSION: service_invocation caller_id must match auth.signer_id")
    if typ == "receipt":
        if p["receipt_id"] == p["request_id"]:
            raise WtpError("ERR_SCHEMA: receipt_id cannot equal request_id")
        if p["status"] == "rejected" and "error_code" not in p:
            raise WtpError("ERR_SCHEMA: rejected receipt requires error_code")
    if typ == "annotation":
        s = p["selector"]
        if "start" in s and "end" in s and s["end"] < s["start"]:
            raise WtpError("ERR_SCHEMA: negative annotation span")
    if typ == "sync_frame":
        step = p["step"]
        if step == "HELLO" and not p.get("supported_codecs"):
            raise WtpError("ERR_SCHEMA: HELLO sync_frame requires supported_codecs")
        if step == "PRESENCE":
            if "presence_state" not in p:
                raise WtpError("ERR_SCHEMA: PRESENCE sync_frame requires presence_state")
        if step == "SYNC_CHUNK":
            if "chunk_b64u" not in p or "chunk_digest" not in p:
                raise WtpError("ERR_SCHEMA: SYNC_CHUNK requires chunk_b64u and chunk_digest")
            raw_chunk = deb64u(p["chunk_b64u"])
            if "sha256:" + hashlib.sha256(raw_chunk).hexdigest() != p["chunk_digest"]:
                raise WtpError("ERR_CONFLICT: sync_frame chunk_digest mismatch")
    if typ == "encrypted_envelope":
        validate_public_key_hex(p["sender_ephemeral_pub"])
        nonce_bytes = deb64u(p["nonce_b64u"])
        if len(nonce_bytes) != 12:
            raise WtpError("ERR_SCHEMA: encrypted_envelope nonce must be 12 bytes")
        ct_bytes = deb64u(p["ciphertext_b64u"])
        if len(ct_bytes) < 16:
            raise WtpError("ERR_SCHEMA: encrypted_envelope ciphertext shorter than Poly1305 tag")
    if typ == "node_meta":
        ep = p["endpoints"]
        validate_federation_endpoint(ep["base_url"])
        for k, v in ep.items():
            if k != "base_url" and not v.startswith("/_wutong/"):
                raise WtpError(f"ERR_SCHEMA: endpoint path {k} must start with /_wutong/")
    if typ == "subscription":
        parse_time(p["expires_at"])
        if not occ_dt < parse_time(p["expires_at"]):
            raise WtpError("ERR_SCHEMA: subscription expires_at must be after occurred_at")
    return True
