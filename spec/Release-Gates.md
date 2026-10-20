# Wutong Protocol v0.1.0 Release Gates & Conformance Governance

> Status: **Formal Specification Release (`v0.1.0`)** (2026-10-18). All normative specification, wire, cryptographic, sync, federation, E2EE, and multi-language conformance gates (`G01`–`G11`) are verified and closed in this release package.

## 1. Release Gate Closure Matrix (`rc.1` → `rc.2` → `v0.1.0`)

| Gate ID | Gate / Measurable Acceptance | `rc.1` | `rc.2` | `v0.1.0` Formal Release Evidence |
|---|---|---|---|---|
| **G01** | Registry namespace, server-independent schema ID, frozen wire & test vectors | BLOCKED | RESOLVED (17 kinds) | **CLOSED (v0.1.0)**: `urn:wutong:schema:core:0.1.0`, **21 normative kinds**, OpenAPI 3.1.0 spec, JCS + dCBOR + E2EE + SHA-256 golden vectors |
| **G02** | Multi-runtime independent Core parser, JCS, dCBOR & Ed25519 verification | BLOCKED | PARTIAL | **CLOSED (3 Independent Runtimes)**: Python 3.11, Node.js 18, and C++23 (GCC 12 / OpenSSL 3) independently implement and cross-verify JCS, dCBOR, and Ed25519 signatures across all 21 kinds |
| **G03** | End-to-end object import/export, DAG, Annotation & Interop loop conformance | BLOCKED | RESOLVED | **CLOSED (v0.1.0)**: `RevisionDAG` cycle/topological verifier, `reanchor_annotation` (`resolved`/`stale`/`orphan`), and `InteropProjectionTracker` loop blocker verified |
| **G04** | Key binding and identity bootstrap (trust roots, key rotation, historical verification) | BLOCKED | RESOLVED | **CLOSED (v0.1.0)**: `wutong.key_binding`, `KeyRegistry`, `previous_key_id` rotation, `authority_id`, and `mode="archive"` vs `mode="live"` verification |
| **G05** | Persisted nonce/idempotency ledger; clock-skew, replay and equivocation suite | BLOCKED | RESOLVED | **CLOSED (v0.1.0)**: SQLite `DurableReplayLedger` (`WAL` + `synchronous=FULL`), idempotent retry cache, and `ERR_EQUIVOCATION` audit table |
| **G06** | Capability security: signature, delegation attenuation, revocation freshness, fail-closed | BLOCKED | RESOLVED | **CLOSED (v0.1.0)**: `authorize_signed_capability_chain` verifies Ed25519 proofs on every hop, checks `wutong.revocation`, and enforces fail-closed `ERR_REVOCATION_STALE` |
| **G07** | OS-safe FileCoordinator & crash-recoverable dual-store commits | BLOCKED | ADVANCED | **CLOSED (POSIX/Linux + C++23/Python)**: `O_NOFOLLOW` + `fstatat(AT_SYMLINK_NOFOLLOW)` + `(st_dev, st_ino)` CAS, mode preservation, orphan cleanup, and Python/C++23 `WriteIntent` recovery |
| **G08** | Canonicalization edge-case vectors (RFC 8785 UTF-16 & RFC 8949 §4.2.1 dCBOR) | PARTIAL | RESOLVED (JCS) | **CLOSED (JCS + dCBOR)**: RFC 8785 UTF-16 supplementary-plane sorting (`U+10348` < `U+E000`) and RFC 8949 §4.2.1 dCBOR length-first bytewise key sorting + non-minimal integer rejection |
| **G09** | Space E2EE, WTP-Sync convergence & WTP-Federation SSRF-hardened exchange | BLOCKED | BLOCKED | **CLOSED (v0.1.0)**: `SpaceEpochKeyring` (X25519+HKDF-SHA256+ChaCha20-Poly1305), `synchronize_replicas` two-node convergence, and `FederationNode` + `validate_federation_endpoint` (`ERR_SSRF_BLOCKED`) |
| **G10** | Protocol spec editorial completeness, critical extension negotiation & 16 `ERR_*` codes | PARTIAL | RESOLVED | **CLOSED (v0.1.0)**: Top-level `critical` extension fail-closed negotiation (`ERR_VERSION`), 16 normative error codes, and OpenAPI 3.1.0 HTTP mapping |
| **G11** | Complete legal AGPL-3.0 license text, SPDX headers, and third-party notices | BLOCKED | RESOLVED | **CLOSED (v0.1.0)**: Verbatim GNU AGPL v3.0 `LICENSE`, `THIRD_PARTY_NOTICES.md`, and SPDX headers across all files |
