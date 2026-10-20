# Wutong Protocol（梧桐协议）v0.1.2 深度技术审查与三语言合规验证报告

> **文档编号**：WTP-DOC-04  
> **文档类型**：深度对抗性审查与可重复合规验证报告（Conformance & Security Audit Report）  
> **验证对象**：`Wutong Protocol v0.1.2`（`WTP-STD-001` 正式规范与三语言参考实现包）  
> **验证日期**：2026-10-18  
> **测试环境**：Linux x86_64 · Python 3.11 + `cryptography` + `jsonschema` · Node.js 18 (`node:crypto`) · GCC C++23 (`-std=c++23 -Wall -Wextra` + `ASan/UBSan`) + OpenSSL 3 + SQLite 3

## 1. 执行摘要（Executive Summary）

本报告记录了对梧桐计划（Project Wutong）与梧桐协议（Wutong Protocol）开展的**第三轮深度协议与密码学对抗性审查**（演进至 `v0.1.2` / `WTP-STD-001`）及实机自动化验证结果：

- **规范消息规模**：从 `v0.1-rc.1`（15 类）→ `v0.1-rc.2`（17 类）→ `v0.1.0`（21 类）→ `v0.1.1`（22 类）正式扩展并闭合为 **24 类规范消息**（新增 `wutong.service_invocation` 与 `wutong.receipt`，Schema `$id`: `urn:wutong:schema:core:0.1.2`）。
- **Python 3.11 + Node.js 18 协议测试套件**：**143 项测试全部通过（143 passed, 0 failed）**。
- **C++23 离线核心、JCS、原生二进制 `dCBOR` 编解码与崩溃恢复套件**：**30 组核心断言全部通过**，并在 **AddressSanitizer + UndefinedBehaviorSanitizer（`ASan + UBSan`, `detect_leaks=1`）** 下零内存错误、零未定义行为、零编译警告。
- **跨语言（Python ↔ Node.js ↔ C++23）互操作验证**：7 组二进制 SHA-256 向量、BMP 与辅助平面（`U+10348` vs `U+E000`）[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) 排序、复杂嵌套对象 [RFC 8949 §4.2.1 `dCBOR`](https://www.rfc-editor.org/rfc/rfc8949.html) 双向编解码，以及 **全部 24 类规范消息的 JSON（JCS）与二进制 CBOR（dCBOR）Ed25519 签名与原始字节直接验签 100% 字节级一致**。
- **Schema 与 OpenAPI 3.1.0 严格验证**：24 个 `v0.1.2` 示例 + 9 个 Legacy 示例 + **132 项负向 Schema 拒绝断言** + [OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0.html) 7 端点契约全部通过。

## 2. 第三轮深度审查（`v0.1.1` → `v0.1.2`）发现的 4 项关键缺口与闭环修复

| 缺陷编号 | 审查发现的深层协议/实现缺口 | `v0.1.2` 规范与代码级实质修复 | 验证用例 |
|---|---|---|---|
| **AUD-301** | **请求/响应线格式不对称**：`v0.1.1` 定义了 `wutong.service` 与联邦 `/_wutong/v0.1/invocations` 端点，但缺乏专门的调用请求原语与带签名的执行回执原语，导致 RPC 调用与错误响应无法作为标准 `WutongEnvelope` 签名归档。 | 新增第 23 类 `wutong.service_invocation` 与第 24 类 `wutong.receipt`；升级 `FederationNode.invoke_protected_action` 验证调用签名与 `wutong.capability` 链后，返回与 `request_digest` 绑定的已签名 `wutong.receipt` 信封。 | `test_service_invocation_and_signed_receipt_closure` |
| **AUD-302** | **私钥失窃（`compromised`）场景下的历史时间戳倒填攻击**：`v0.1.1` 对所有撤销统一按 `effective_from <= at_time` 判断；若私钥失窃（`reason="compromised"`），攻击者可将伪造信封的 `auth.issued_at` 倒填至 `effective_from` 之前，从而骗过 `mode="archive"` 归档验签。 | 升级 `KeyRegistry.is_revoked` 与 `lookup_key`：当 `reason == "compromised"` 时，默认拒绝该密钥在一切时间戳下的未公证签名（`ERR_KEY_REVOKED`），仅当具备撤销前独立透明日志/时间戳公证（`notarized_before_revocation=True`）时放行；同时在 `semantic.py` 强制限制 `abs(occurred_at - auth.issued_at) <= 300s`。 | `test_key_compromise_retroactive_rejection_vs_notarized_archive` |
| **AUD-303** | **能力委托链（Capability Chain）签发时间倒置漏洞**：子能力虽校验了 `[not_before, expires_at]` 区间子集，但未校验子能力的 `auth.issued_at` 是否早于父能力签发时间或超出父能力生效窗口（违反 [UCAN Delegation](https://ucan.xyz/delegation/) 时序单调性）。 | 在 `authorize_chain` 与 `authorize_signed_capability_chain` 中强制校验 `parent.auth.issued_at <= child.auth.issued_at` 且 `parent.not_before <= child.auth.issued_at < parent.expires_at`。 | `test_capability_temporal_issuance_monotonicity` |
| **AUD-304** | **C++23 缺少原生二进制 `dCBOR` 解码器 & `WTP-Sync` 瞬态 Presence 未与持久化 DAG 隔离**：`v0.1.1` 的 C++23 仅实现 JSON→dCBOR 编码器；且 `wutong.sync_frame` 虽列举了 `PRESENCE` 步骤，但缺少标准荷载字段与非持久化隔离处理。 | 在 `reference/src/core.cpp` 实现完整原生二进制 `DcborDecoder`（`dcbor_to_jcs`、`verify_raw_cbor_hex_envelope`），直接拦截非最短整数、不定长、原始字节串与乱序键；在 `SyncReplica` 新增 `build_presence_frame` 与 `ingest_presence_frame`（强制 `1 <= ttl_seconds <= 60` 且不污染 `chunks`/`heads`）。 | `test_core.cpp`, `test_crosslang.py`, `test_sync_ephemeral_presence_isolated_from_durable_dag` |

## 3. 累计三轮审查（24 项核心缺陷）全量闭环矩阵

| 类别 | 已闭环的关键机制 | 覆盖模块 |
|---|---|---|
| **线格式与双编码确定性** | 严格 JSON（禁 `NaN`/`Infinity`/浮点数/重复键/孤立代理项）、[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) UTF-16 码元排序、[RFC 8949 §4.2.1 `dCBOR`](https://www.rfc-editor.org/rfc/rfc8949.html) 双向编解码、`proof.encoding` 跨网关无损验签 | `wire.py`, `cbor_wire.py`, `core.cpp`, `jcs_node.cjs`, `dcbor_node.cjs` |
| **密码学与零信任安全** | [RFC 8032 §5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html) 标量 `0 <= S < L` 防延展性、低阶/全零公钥拦截、X25519 全零共享密钥拦截、`wutong.space_epoch` 多成员密钥封装、密钥失窃防回溯伪造、时序单调能力委托 | `wire.py`, `policy.py`, `e2ee.py`, `core.cpp` |
| **本地优先与原生文档保真** | POSIX `O_NOFOLLOW` + `fstatat(AT_SYMLINK_NOFOLLOW)` + `(st_dev, st_ino)` CAS、SQLite `WAL + synchronous=FULL` 三阶段崩溃恢复、Source-First 字节范围补丁 `patches`、[W3C PROV-O](https://www.w3.org/TR/prov-o/) 自审与凭据泄露拦截 | `filecoord.py`, `document_patch.py`, `core.cpp` |
| **分布式同步、联邦与互操作** | `SyncReplica` 传递性因果闭包与 `snapshot/1` 压缩水位线回退、瞬态 `PRESENCE` 帧隔离、`FederationNode` SSRF 阻断/速率限制/有界分页/[RFC 9530 `Content-Digest`](https://www.rfc-editor.org/rfc/rfc9530.html)、`wutong.service_invocation` → `wutong.receipt` 闭环、`RevisionDAG` 环检测、[W3C 批注重锚定](https://www.w3.org/TR/annotation-model/)、`InteropProjectionTracker` 回声防环 | `sync.py`, `federation.py`, `replay.py` |

## 4. 实机自动化测试结果明细

执行 `bash tools/run_conformance.sh` 的实机输出摘要如下：

| 测试阶段 | 执行命令 | 通过指标 | 耗时 / 状态 |
|---|---|---|---|
| **阶段 1：Python 3.11 + Node.js 18 全量协议测试** | `PYTHONPATH=src python3 tests/test_protocol.py` | **143 passed, 0 failed**（覆盖 24 类正负向 Schema、24 类语义、JCS/dCBOR、E2EE、Sync、Federation、RPC Receipt、Key Compromise、FileCoordinator） | `PASS (exit 0)` |
| **阶段 2A：C++23 核心、JCS、原生 dCBOR 与崩溃自愈** | `/tmp/wutong-poc-make/wutong_core_tests` | **30 组核心断言全部通过**（含 `Prepared`/`Replaced`/`Committed` 崩溃恢复与原生二进制 `dCBOR` 7 项负向拦截） | `PASS (exit 0)` |
| **阶段 2B：三语言（Python/Node/C++23）跨语言互操作** | `python3 tests/test_crosslang.py ...` | **7 组 SHA-256 + 3 组复杂 JCS/dCBOR 双向编解码 + 辅助平面排序 + 24 类 JSON/CBOR 双格式签名跨语言验签** | `PASS (exit 0)` |
| **阶段 2C：双代次 Schema 与 OpenAPI 3.1.0 校验** | `python3 tests/test_schema.py` | **24 个 v0.1.2 示例 + 9 个 Legacy 示例 + 132 项负向 Schema 拦截 + OpenAPI 3.1.0 校验** | `PASS (exit 0)` |
| **阶段 3：C++23 ASan + UBSan 内存与未定义行为消毒** | `ASAN_OPTIONS=detect_leaks=1 /tmp/wutong-poc-asan/wutong_core_tests` | **0 memory leaks, 0 address errors, 0 undefined behavior** | `PASS (exit 0)` |

## 5. 跨语言固定密码学测试向量（Pinned Conformance Vectors）

1. **Ed25519 确定性种子与公钥（Seed `0x00..0x1f`）**：
   - `private_seed_hex`: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
   - `public_key_hex`: `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`
2. **RFC 8785 JCS 辅助平面 UTF-16 码元序向量**：
   - 输入：`{"\uE000": 1, "𐍈": 2}`（其中 `U+10348` UTF-16 为 `0xD800 0xDF48`，`U+E000` UTF-16 为 `0xE000`）
   - 规范化输出（Python / Node.js / C++23 完全一致）：`{"𐍈":2,"\ue000":1}`
3. **RFC 8949 §4.2.1 `dCBOR` 键长优先字典序向量**：
   - 输入：`{"aa":1,"b":2,"a":0}`
   - 规范化 `dCBOR` 十六进制（Python / Node.js / C++23 双向一致）：`a361610061620262616101`
4. **固定 `wutong.object` JCS 签名信封向量**：
   - 规范化待签名字节 SHA-256：`61dc379fc339fa4fc118fc4ce42ff9ad828ab83dc780ff23b56c7ebbd7836e36`
   - `proof.sig`（Base64URL）：`91bbF7H1wMhm5Pif0c6nG6uvkwf02UX3wbX54wsBbB2-KYPl63TLqCKke2LGYakkrDCW4Fzq93_LYB4mkhFjCQ`
