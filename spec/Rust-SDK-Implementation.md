# Rust Core / Network / Server / SDK implementation blueprint

## 1. Engineering baseline

| Subsystem | Language | Expected packaging |
|---|---|---|
| Qt UI, high-fidelity document surface | C++23 + Qt 6.12.0 LTS | native GUI executables |
| Core local C++ document services | C++23 | native libraries (no network dependency) |
| WTP Core wire & policy | Rust Edition 2024 | reusable crates, versioned schema bindings |
| Wutong Network backend `networkd` | Rust Edition 2024 | optional user-controlled daemon |
| Wutong Server | Rust Edition 2024 | modular headless binary |
| Wutong CLI | Rust Edition 2024 | local-by-default commands, optional RPC |
| Wutong SDK | C++, C#, Python, Rust, Go, TypeScript | idiomatic libraries; protocol conformance suite |

**Do not couple** plain local Writer/Knowledge/Publisher to networkd availability. Network GUI may launch/connect/stop an explicitly installed background service; must support offline cache. No silent auto-enable of sync, federation or AI agents.

## 2. Recommended Rust workspace (to implement; not compiled in this kit)

```text
rust/
  crates/wtp-types       # stable ID/Schema model; no transport
  crates/wtp-wire        # strict JSON/JCS/signature, size/time limits
  crates/wtp-policy      # Principal, root control, Capability evaluation
  crates/wtp-agent       # Task state, artifacts, approvals
  crates/wtp-document    # byte digests, normalized *metadata* not content
  crates/wtp-sync        # codec negotiation, optional CRDT implementations
  crates/wtp-federation  # resolver, subscription, HTTP gateway
  crates/wtp-service     # service spec, safe execution interface
  crates/wtp-interop     # adapter SPI, projections, external binding
  crates/wtp-storage     # migrations, SQLite, Blob, write intents
  bins/wutong-networkd
  bins/wutong-server
  bins/wutong
```

Core libs should not contain Qt, native GUI or cloud/vendor hard dependencies. Prefer `serde` (with strict duplicate-key visitor rather than naive `Value` parsing), `jsonschema`, a reviewed JCS implementation, `ed25519-dalek`/audited signature toolkit, SQLite, and Tokio where async needed. **These are candidates, not audited dependency picks.** Cargo edition `2024`, MSRV and lockfile policy must be declared after CI build.

## 3. Cross-language strategy

Use one **wire conformance contract** but idiomatic type/model implementations for each language. Generated Schema types simplify ergonomics but may omit constraints like duplicate-key rejection, content digest validation, key trust and permission policy.

| SDK | Network client | Offline capability | Checks |
|---|---|---|---|
| C++ | C++23 HTTP/IPC | C++ local Core | UTF-8/UTF-16, span lifetime, binary content, Qt isolation |
| C# | async .NET HttpClient | optional binding | cancellation token, System.Text.Json strict settings, nullable state |
| Python | sync/async client | pure Python or optional native | float/NaN rejection, typed models, async timeouts |
| Rust | async request API | native crates | ownership, error enum, Send/Sync limits |
| Go | context-aware HTTP | Go local model/read | no implicit float64 loss, strict raw decoder, context cancellation |
| TypeScript | Fetch/WebSocket | optional IndexedDB | max-safe-integer, UTF-16/JCS, browser auth storage |

- Recommended interoperability starting point: signed Object/Revision/Task/Proposal messages, SHA-256, error mapping and profile negotiation.
- SDK compatibility requires wire conformance tests plus negative vectors (duplicate keys, overlong UUID, malicious auth/relative path, unsupported critical profile, replay).
- C++ ↔ Rust integration for network: local authenticated IPC with version negotiation; use C ABI **only for carefully bounded APIs** with explicit allocation/free functions and panic/exception boundaries.
- Never require a Python interpreter/Node runtime for a basic Writer installation.

## 4. Build and release matrix

- Windows 10/11 x64 and arm64 where practical; MSVC C++23/Qt, rustc target Windows.
- Linux x64/arm64 (X11/Wayland) and headless server.
- macOS arm64/x64 (Qt/native platform integrations).
- CI: cargo fmt, clippy, `cargo test`, fuzzing, `cargo deny`/license checks, CMake C++ tests, ASan/UBSan, cross-SDK integration suite.
- Code signing and SBOM provenance for all binary installers; AGPL compliance verification for distribution and modified network services.

## 5. Suggested work order

1. Independent Rust strict JSON/parser + tested JCS and signed-envelope verification using locked vectors.
2. Root key binding, delegated Capability and durable replay/nonce state; explicit offline policy.
3. Crash-recoverable local FileCoordinator with OS-specific safe handle APIs and scoped path authorization.
4. Rust Network daemon with opt-in lifecycle and authenticated local IPC.
5. Two test nodes exchanging Objects, Revisions and signed Events; keep Sync codec separate.
6. Add C# / Go / TypeScript / Python SDK network paths from the exact same conformance fixtures.
