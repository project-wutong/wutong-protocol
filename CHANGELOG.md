# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Spec revisions follow `v0.1.x`;
the wire protocol identifier stays `wutong/0.1` until a breaking change is approved via WIP.

## [Unreleased]

### Added
- Repository hosting of the `v0.1.2` engineering kit; `docs/` now contains the four formal documents
  referenced by the README (architecture v1.4, WTP-STD-001, release guide, conformance report).
- `spec/history/WTP-000-v0.1.0-rc.1.md` (original 15-kind RC specification, for traceability).
- `tools/gen_crosslang_vectors.py` and `vectors/crosslang/` — vectors consumed by the Rust core and SDKs.
- WIP (Wutong Improvement Proposal) process: `wip/WIP-0000-template.md`.
- CI: Python + Node conformance, C++23 reference (CMake, ASan/UBSan), schema/vector drift checks.


## `v0.1.2` (`WTP-STD-001` Formal Standard Release — 2026-10-18)

- **24 Normative Message Kinds (`urn:wutong:schema:core:0.1.2`)**: Added `wutong.service_invocation` (Kind 23) and `wutong.receipt` (Kind 24) to close the protected request/response wire loop across `WTP-Service` and `WTP-Federation`.
- **Key Compromise Retroactive Defense (`WTP-Security`)**: Distinguished `reason == "compromised"` from `reason == "superseded"` in `KeyRegistry.is_revoked` and `lookup_key`, rejecting unnotarized historical signatures across all timestamps when a key is compromised while preserving notarized archive verification (`notarized_before_revocation=True`).
- **Temporal Capability Delegation Monotonicity (`WTP-Security` / `WTP-Agent`)**: Enforced `parent.auth.issued_at <= child.auth.issued_at` and `parent.not_before <= child.auth.issued_at < parent.expires_at` on multi-hop `wutong.capability` chains, plus `abs(occurred_at - auth.issued_at) <= 300s` on signed envelopes.
- **Native Binary `dCBOR` Decoder & Direct CBOR Envelope Verifier in C++23 (`reference/src/core.cpp`)**: Added `dcbor_to_jcs`, `dcbor_hex_to_jcs`, and `verify_raw_cbor_hex_envelope` with strict RFC 8949 §4.2.1 shortest-length integer checks, map key bytewise order validation, and raw CBOR Ed25519 signature verification across all 24 message kinds.
- **Ephemeral `PRESENCE` Sync Frames (`WTP-Sync`)**: Added `presence_state` (`online`/`typing`/`viewing`/`idle`) and bounded `ttl_seconds` (`1..60`) on `wutong.sync_frame`, isolated from the durable `RevisionDAG`.
- **Formal Standard Specification (`WTP-STD-001`)**: Added standalone IETF RFC-style formal protocol standard specification (`02_Wutong_Protocol_v0.1.2_Formal_Standard_Specification.md`).
