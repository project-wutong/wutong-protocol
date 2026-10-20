# Security Design Review — Wutong Protocol `v0.1.0-rc.2`

## 1. Trust Boundaries

1. `Native user filesystem` ↔ `Wutong Document Core`: untrusted symlinks/mounts, external file writers, metadata and permissions.
2. `Local Core` ↔ `Optional Network daemon`: authenticated local IPC (UDS/Named Pipe with OS ACL), isolated identities/credential storage, version pinning.
3. `Local/Network` ↔ `Unknown remote peer`: TLS, signed objects, `wutong.key_binding` control, capability and durable replay/equivocation policy, memory bounds.
4. `Knowledge/Agent` ↔ `Untrusted knowledge and tools`: content/commands separation, execution policy, capability attenuation, and human review.
5. `Network/Builder` ↔ `Platform adapter`: credential isolation, anti-SSRF, rate limiting, idempotency, disclosure of projection loss.
6. `Publication` ↔ `Federation`: private→public boundary, explicitly selected revisions, non-retractable caching risk.

## 2. Security Threats Resolved in `v0.1.0-rc.2`

- **Principal-to-Key Binding & Rotation (`wutong.key_binding`)**: Principals no longer rely on unverified UUID strings. `KeyRegistry` validates signed key bindings, key purposes (`signing`, `delegation`, `authentication`, `assertion`), validity intervals (`valid_from`..`valid_until`), and `previous_key_id` rotation signatures.
- **Signed Revocation & Offline Fail-Closed Policy (`wutong.revocation`)**: Compromised or superseded keys and delegated capabilities can be revoked via signed `wutong.revocation` envelopes with `effective_from` timestamps. `authorize_signed_capability_chain` enforces a fail-closed freshness budget (`ERR_REVOCATION_STALE`) so offline nodes do not silently accept stale capability chains for sensitive actions.
- **Archive Proof vs Live Invocation Separation**: `verify_envelope` separates `mode="live"` (enforcing a strict 300-second clock-skew window and replay ledger consumption) from `mode="archive"` (verifying historical artifact/revision proofs against the signer's key binding state at `auth.issued_at`).
- **Durable Replay & Equivocation Detection (`DurableReplayLedger`)**: Replaces volatile in-memory tracking with a SQLite `WAL` (`PRAGMA synchronous=FULL`) ledger that persists `(signer_id, nonce, message_id, canonical_digest)` across restarts and records cryptographic equivocation (`ERR_EQUIVOCATION`) whenever an identical `message_id` or `(signer_id, nonce)` is presented with a different canonical digest.
- **Symlink Traversal & Virtualized VFS Hardening (`FileCoordinator`)**: Combines `os.stat(comp, dir_fd=dir_fd, follow_symlinks=False)` (`AT_SYMLINK_NOFOLLOW`), `os.open(..., O_NOFOLLOW | O_CLOEXEC, dir_fd=dir_fd)`, and `os.fstat(fd)` `(st_dev, st_ino)` identity verification at every directory component and leaf file, preventing symlink escapes even on virtualized container filesystems where `O_NOFOLLOW | O_DIRECTORY` alone does not reject directory symlinks.

## 3. Remaining Pre-Production Security Exercises

- Independent third-party cryptographic and protocol audit prior to `v1.0` production claims.
- Native Windows NTFS (`CreateFileW` / reparse point) and macOS APFS (`F_FULLFSYNC`) hardware crash testing.
- Authenticated CRDT framing (verifying `WT-Security` envelopes before passing binary updates into Automerge/Yrs parsers).
- Formal MLS (RFC 9420) group key schedule and member removal forward-secrecy proof for private E2EE spaces.
