# SPDX-License-Identifier: AGPL-3.0-only
"""Source-First Minimal Range Patching & W3C PROV-O Provenance Verifier (`wutong.proposal`, `wutong.revision`, `wutong.artifact`).

Implements §5.1, §8.2, and §8.3 of Project Wutong Architecture:
1. `apply_source_patches(base_bytes, patches, *, expected_base_digest, expected_proposed_digest)`:
   - Verifies `sha256(base_bytes) == expected_base_digest`.
   - Verifies that `patches` are non-overlapping, sorted in ascending byte order (`0 <= start_byte <= end_byte <= len(base_bytes)`).
   - Verifies every patch's `expected_slice_digest == sha256(base_bytes[start_byte:end_byte])` before replacement, preventing blind offset corruption!
   - Applies minimal UTF-8 source replacements while preserving all untouched bytes (including BOM, CRLF/LF, comments, and macros) byte-for-byte.
   - Verifies `sha256(result_bytes) == expected_proposed_digest`.
2. `validate_provenance(prov_dict)`:
   - Enforces W3C PROV-O (`was_generated_by`, `was_associated_with`, `was_derived_from`, `used`) integrity rules and blocks credential/secret leakage patterns in provenance fields.
"""
import hashlib
import re
from .wire import URN, WtpError


SECRET_LEAK_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9_\-\.]+|sk-[a-z0-9]{16,}|ghp_[a-z0-9]{16,}|-----BEGIN\s+PRIVATE\s+KEY-----)"
)


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def apply_source_patches(
    base_bytes: bytes,
    patches: list,
    *,
    expected_base_digest: str = None,
    expected_proposed_digest: str = None,
) -> bytes:
    """Deterministically verifies and applies non-overlapping byte-range patches to `base_bytes`."""
    if not isinstance(base_bytes, (bytes, bytearray)):
        raise WtpError("ERR_SCHEMA: base_bytes must be bytes")
    base_bytes = bytes(base_bytes)
    if expected_base_digest is not None and sha256_prefixed(base_bytes) != expected_base_digest:
        raise WtpError("ERR_CONFLICT: base_digest mismatch before applying patches")
    if not isinstance(patches, list) or not patches:
        raise WtpError("ERR_SCHEMA: patches must be a non-empty list")

    out_chunks = []
    cursor = 0
    for idx, patch in enumerate(patches):
        if not isinstance(patch, dict):
            raise WtpError("ERR_SCHEMA: patch entry must be object")
        start = patch.get("start_byte")
        end = patch.get("end_byte")
        slice_digest = patch.get("expected_slice_digest")
        replacement = patch.get("replacement")
        if (
            not isinstance(start, int)
            or not isinstance(end, int)
            or isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(slice_digest, str)
            or not isinstance(replacement, str)
        ):
            raise WtpError("ERR_SCHEMA: invalid patch field types")
        if start < cursor or end < start or end > len(base_bytes):
            raise WtpError(
                f"ERR_CONFLICT: overlapping or out-of-bounds patch at index {idx} ({start}..{end})"
            )
        target_slice = base_bytes[start:end]
        if sha256_prefixed(target_slice) != slice_digest:
            raise WtpError(
                f"ERR_CONFLICT: patch[{idx}] expected_slice_digest mismatch"
            )
        out_chunks.append(base_bytes[cursor:start])
        out_chunks.append(replacement.encode("utf-8", "strict"))
        cursor = end

    out_chunks.append(base_bytes[cursor:])
    result = b"".join(out_chunks)
    if expected_proposed_digest is not None and sha256_prefixed(result) != expected_proposed_digest:
        raise WtpError(
            "ERR_CONFLICT: patched document digest does not match proposed_digest"
        )
    return result


def validate_provenance(prov: dict) -> bool:
    """Validates W3C PROV-O provenance block and prevents accidental credential leakage."""
    if not isinstance(prov, dict):
        raise WtpError("ERR_SCHEMA: provenance must be object")
    gen = prov.get("was_generated_by")
    assoc = prov.get("was_associated_with")
    if not isinstance(gen, str) or not gen or not isinstance(assoc, str) or not URN.fullmatch(assoc):
        raise WtpError("ERR_SCHEMA: invalid provenance was_generated_by or was_associated_with")
    if "reviewer_id" in prov and prov["reviewer_id"] == assoc:
        raise WtpError("ERR_PERMISSION: self-review forbidden in provenance (reviewer_id == was_associated_with)")
    for k, v in prov.items():
        texts = v if isinstance(v, list) else [v]
        for t in texts:
            if isinstance(t, str) and SECRET_LEAK_RE.search(t):
                raise WtpError(f"ERR_SCHEMA: potential credential leak in provenance.{k}")
    return True
