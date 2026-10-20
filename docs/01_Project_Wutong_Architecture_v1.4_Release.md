# Project Wutong（梧桐计划）总体技术与产品架构方案（v1.4 正式发布终定版）

> **文档编号**：WTP-DOC-01  
> **文档类型**：正式总体架构方案（Formal Release Architecture Baseline）  
> **方案版本**：`1.4`（全面对齐 **`Wutong Protocol v0.1.2` / `WTP-STD-001` 正式标准规范**）  
> **编制日期**：2026-10-18  
> **项目名称**：**Project Wutong（梧桐计划）**  
> **协议名称**：**Wutong Protocol（梧桐协议，`v0.1.2`）**  
> **套件名称**：**Wutong Suit**（正式拼写）  
> **技术基线**：**C++23、Rust Edition 2024、Qt 6.12.0 LTS**  
> **项目自有代码许可证**：**GNU AGPL v3.0 only**（[SPDX `AGPL-3.0-only`](https://spdx.org/licenses/AGPL-3.0-only.html)）

## 摘要

Project Wutong（梧桐计划）是面向人类、组织、Agent 与软件服务的本地优先（Local-First）、原生文档优先（Source-First）、跨平台的知识创作、知识管理、协作、联邦网络与“知识即服务（Knowledge-as-a-Service）”基础设施。本 `v1.4` 正式定稿版在历经三轮深度协议与安全对抗性审查后，将总体架构与 **`Wutong Protocol v0.1.2` 正式标准规范（24 类规范消息，`urn:wutong:schema:core:0.1.2`）** 全面对齐：

1. **24 类规范消息完整闭合八大 Profile（`urn:wutong:schema:core:0.1.2`）**：在 `v0.1.1` 的 22 类原语基础上，新增第 23 类规范原语 `wutong.service_invocation`（受保护服务/RPC/联邦动作调用信封）与第 24 类规范原语 `wutong.receipt`（带签名执行回执与结构化错误响应信封），使“请求（Invocation）→ 授权校验（Capability Chain）→ 执行回执（Signed Receipt）”全链路均为一等公民签名信封。
2. **密钥泄露（Compromised）回溯伪造防御与时序单调能力委托（WTP-Security v0.1.2）**：严格区分密钥“正常轮换替代（`superseded`）”与“私钥失窃泄露（`compromised`）”的归档验签语义——当密钥因 `compromised` 被撤销时，拒绝一切未经撤回前独立公证（Notarized）的自报历史时间戳签名，彻底阻断攻击者利用失窃私钥倒填 `auth.issued_at` 伪造历史归档记录；同时强制校验多跳 `wutong.capability` 委托链的签发时间单调性（`parent.auth.issued_at <= child.auth.issued_at` 且落入父能力有效窗口，对齐 [UCAN Delegation Spec](https://ucan.xyz/delegation/)）。
3. **三语言（Python 3.11 / Node.js 18 / C++23）全原生 JCS 与二进制 dCBOR 编解码及验签闭环**：C++23 参考核心（`reference/src/core.cpp`）不仅实现严格 JSON 解析、[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) UTF-16 码元序规范化与 [RFC 8949 §4.2.1 Deterministic CBOR (`dCBOR`)](https://www.rfc-editor.org/rfc/rfc8949.html) 编码器，而且在 `v0.1.2` 中新增**原生二进制 `dCBOR` 解码器与原始 CBOR 信封直接验签器**，在 C++23 层直接拦截非最短整数编码、不定长容器、原始字节串、乱序/重复 Map 键与尾部垃圾字节。
4. **Source-First 最小范围补丁、W3C PROV-O 溯源与瞬态在线状态（Presence）隔离**：`wutong.proposal` 内建字节范围补丁 `patches` 与 [W3C PROV-O](https://www.w3.org/TR/prov-o/) `provenance`；`wutong.sync_frame` 的 `PRESENCE` 帧支持经过签名的瞬态在线状态（`online`/`typing`/`viewing`/`idle`）与有界生存期（`1 <= ttl_seconds <= 60`），并与持久化 `RevisionDAG` 严格隔离。

## 1. Wutong Suit 产品矩阵与进程边界

| 正式名称 | 类型与技术栈 | 离线独立能力（零网络/零后台依赖） | 网络/协作可选增强 |
|---|---|---|---|
| **Wutong Writer** | C++23 + [Qt 6.12.0 LTS](https://doc.qt.io/qt-6.12/qt-releases.html) / QML | 原生文件直读直写、无损字节往返、增量解析、最小范围补丁（`apply_source_patches`） | 远程协作会话、Agent 范围补丁提案（`wutong.proposal`）与瞬态 `PRESENCE` 光标状态 |
| **Wutong Knowledge** | C++23 + Qt 6.12.0 LTS / QML | 本地 Vault、`RevisionDAG`、关系图谱、[W3C 批注重锚定](https://www.w3.org/TR/annotation-model/)、SQLite FTS 检索 | 多成员 E2EE 空间同步（`wutong.space_epoch` + `wutong.encrypted_envelope` + `wutong.sync_frame`） |
| **Wutong Publisher** | C++23 + Qt 6.12.0 LTS / QML | 本地 [Typst](https://github.com/typst/typst)/LaTeX/[Pandoc](https://pandoc.org/) 排版编译、文献引用检查、PDF/EPUB/HTML 导出 | 联合出版投射（`wutong.publication`）与撤回（`withdrawn`）生命周期 |
| **Wutong Network** | C++23/Qt GUI + **用户可选 Rust 2024 `wutong-networkd`** | 节点配置、Ed25519/X25519 密钥与撤销管理、防回溯历史归档验签（`mode="archive"`） | 后台同步、联邦解析/订阅、带签名回执的受保护调用（`wutong.service_invocation` → `wutong.receipt`） |
| **Wutong Builder** | C++23/Qt GUI + Rust 服务构建器 | 本地 `wutong.service` 规范设计、静态站点构建与本地预览 | 部署至 `wutong-server`、防回环双向外部平台绑定（`wutong.external_binding`） |
| **Wutong CLI** | [Rust Edition 2024](https://doc.rust-lang.org/edition-guide/rust-2024/index.html) (`wutong`) | 本地文档校验、最小补丁应用、JCS/dCBOR 签名验签、索引构建 | 连接本地 `wutong-networkd` 或远程 `wutong-server` |
| **Wutong SDK** | C++23 / C# / Python / Rust / Go / TypeScript | 本地模型校验、JCS/dCBOR 编解码、离线归档验签 | [OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0.html) 客户端、WebSocket/SSE 订阅与同步 |
| **Wutong Server** | Rust Edition 2024 Headless (`wutong-server`) | 不适用（显式自托管服务端） | Sync Relay、Federation 网关、Service Host、Adapter Gateway、Agent Worker |

## 2. 八大协议子集（Profiles）与 24 类规范消息全景架构

| Profile 标识 | 核心职责 | 归属的规范消息类型（共 24 类） |
|---|---|---|
| **1. `WTP-Core`** | 主体、空间、对象、版本 DAG、语义关系与审计事件 | `wutong.principal`, `wutong.space`, `wutong.object`, `wutong.revision`, `wutong.relation`, `wutong.event` |
| **2. `WTP-Document`** | 原生文件绑定、W3C 多重定位批注与最小字节补丁 | `wutong.annotation`（配合 `wutong.object.binding` 与 `wutong.proposal.patches`） |
| **3. `WTP-Agent`** | Agent 能力清单、提案审查、任务状态机与产物溯源 | `wutong.proposal`, `wutong.task`, `wutong.agent_manifest`, `wutong.artifact` |
| **4. `WTP-Security`** | Ed25519/X25519 密钥绑定、撤销、能力委托与多成员 E2EE | `wutong.key_binding`, `wutong.revocation`, `wutong.capability`, `wutong.space_epoch`, `wutong.encrypted_envelope` |
| **5. `WTP-Sync`** | 多端因果闭包同步、压缩快照回退与瞬态在线状态 | `wutong.sync_frame`（`HELLO`, `AUTH`, `SYNC_OFFER`, `SYNC_REQUEST`, `SYNC_CHUNK`, `SYNC_ACK`, `PRESENCE`） |
| **6. `WTP-Federation`** | 联邦节点元数据、联合出版、有界分页订阅与签名回执 | `wutong.publication`, `wutong.node_meta`, `wutong.subscription`, `wutong.receipt` |
| **7. `WTP-Service`** | 声明式知识即服务（KaaS）定义与受保护服务调用 | `wutong.service`, `wutong.service_invocation` |
| **8. `WTP-Interop`** | 外部平台防回环双向桥接与有损投射报告 | `wutong.external_binding` |

## 3. 核心架构深化机制（v1.4）

### 3.1 Source-First 最小范围补丁与 W3C PROV-O 溯源

为彻底兑现“不通过 AST 全文重序列化破坏用户原生文件格式”的承诺，Agent 或协作者提交 `wutong.proposal`（`intent="patch"`）时，可附带有序非重叠字节补丁数组 `patches`：

```json
{
  "start_byte": 17,
  "end_byte": 33,
  "expected_slice_digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "replacement": "经 Agent 最小补丁修订的段落 A。"
}
```

执行器（`apply_source_patches`）在应用补丁时强制验证：
1. 原文件整体字节哈希等于 `base_digest`；
2. 每个补丁的 `[start_byte, end_byte)` 范围单调递增且互不重叠；
3. 原文件在 `[start_byte, end_byte)` 处的精确切片字节哈希等于 `expected_slice_digest`；
4. 替换后生成的完整字节流哈希精确等于 `proposed_digest`，其余未触及区段的 BOM、CRLF/LF、LaTeX/Typst 宏与注释保持 100% 字节不变。

同时，`provenance` 字段严格遵循 [W3C PROV-O](https://www.w3.org/TR/prov-o/)，强制要求 `reviewer_id != was_associated_with`（禁止 Agent 自提自审），并内置正则扫描拦截误写入溯源元数据的 Bearer Token、API Key 或私钥文本。

### 3.2 本地文件与 SQLite 双相崩溃恢复协调器（`FileCoordinator`）

在桌面端（C++23 `wutong::Store`）与服务端/参考引擎（Python `FileCoordinator`）中，原生文件替换严格执行 **Prepare → Atomic Replace → Finalize** 三阶段协议：
1. **防符号链接与目录穿越**：在 POSIX 系统上通过 `O_NOFOLLOW` 与 `fstatat(AT_SYMLINK_NOFOLLOW)` 逐级校验工作区路径及父目录，绑定 `(st_dev, st_ino)` 防止 TOCTOU 竞态替换。
2. **持久化 `WriteIntent` 日志**：先将新内容写入同目录隐藏临时文件 `.wutong-<intent>.pending` 并执行文件级与父目录级 `fsync`，随后在 SQLite（`WAL` + `synchronous=FULL`）中记录 `status='prepared'` 的 `WriteIntent`。
3. **确定性崩溃自愈**：无论进程在 `Prepared`、`Replaced` 或 `Committed` 任意阶段崩溃，重启后 `recover_intents()` 均可根据磁盘文件当前 SHA-256 与临时文件哈希自动完成幂等前滚（`rolled-forward`）或结清（`finalized`）；若外部编辑器在崩溃期间修改了原文件，则安全标记为 `conflict`，绝不覆盖用户外部修改。

### 3.3 请求/回执闭环（`wutong.service_invocation` → `wutong.receipt`）与密钥失窃回溯防御

1. **受保护调用与签名回执**：调用方通过 `wutong.service_invocation` 提交动作、目标资源与关联的 `capability_ids`；服务节点验证签名、重放账本与 `wutong.capability` 委托链后，返回由服务节点算子签名的 `wutong.receipt` 信封（内含 `request_id`、`request_digest`、`status` 及可选 `error_code` / `result_digest` / `applied_revision_id`），实现不可抵赖的双向审计。
2. **密钥失窃（`compromised`）回溯伪造拦截**：当 `wutong.revocation` 的 `reason == "compromised"` 时，`KeyRegistry` 在归档模式（`mode="archive"`）下默认拒绝该密钥在任何自称时间戳下的未公证签名，防止持失窃私钥的攻击者通过伪造早于 `effective_from` 的 `auth.issued_at` 注入恶意历史版本；仅当历史信封具备撤销前独立公证证明（`notarized_before_revocation=True`）时才予放行。
