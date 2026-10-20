# Wutong Protocol（梧桐协议）v0.1.2 正式标准规范（Formal Protocol Standard Specification）

> **标准编号**：`WTP-STD-001`  
> **协议版本**：`wutong/0.1`（规范修订版 `v0.1.2`）  
> **Schema 标识符**：`urn:wutong:schema:core:0.1.2`  
> **文档状态**：**Standards Track — Formal Release Specification（正式标准规范）**  
> **发布日期**：2026-10-18  
> **许可证**：[GNU AGPL v3.0 only](https://spdx.org/licenses/AGPL-3.0-only.html)（`SPDX-License-Identifier: AGPL-3.0-only`）

## 1. 范围、规范性术语与协议标识

### 1.1 范围（Scope）
本标准规范（`WTP-STD-001`）定义了 **Wutong Protocol（梧桐协议，`v0.1.2`）** 的完整线格式（Wire Format）、通用消息信封（`WutongEnvelope`）、24 类规范消息荷载（Payload Schemas）、密码学签名与多成员端到端加密（E2EE）算法、能力委托与撤销验证状态机、多端因果同步协议（`WTP-Sync`）、联邦与知识即服务 HTTP/HTTPS 传输绑定（`WTP-Federation` / `WTP-Service`）以及 16 类标准错误码。任何声称兼容 `wutong/0.1` 的桌面客户端、CLI、SDK、Agent 运行时或服务端实现，均必须满足本规范定义的规范性要求。

### 1.2 规范性术语（Normative Requirements Notation）
本文档中的关键字 **“MUST”**、**“MUST NOT”**、**“REQUIRED”**、**“SHALL”**、**“SHALL NOT”**、**“SHOULD”**、**“SHOULD NOT”**、**“RECOMMENDED”**、**“NOT RECOMMENDED”**、**“MAY”** 和 **“OPTIONAL”** 均按照 [BCP 14](https://www.rfc-editor.org/info/bcp14)（[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) 与 [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)）予以解释，且仅当其以全大写字母出现时具备上述规范性含义。

### 1.3 协议版本与类型前缀
1. 所有符合本规范的顶层消息信封，其 `protocol` 字段的值 **MUST** 精确为字符串 `"wutong/0.1"`。
2. 所有规范消息类型标识（`kind`）**MUST** 使用小写点分命名空间 `"wutong.<kind_name>"`。
3. 任何实现收到 `protocol != "wutong/0.1"` 的信封时，**MUST** 立即以 `ERR_VERSION` 拒绝处理。

## 2. 基础数据类型与 ABNF 语法规范

### 2.1 全局唯一标识符（UUIDv7 URN）
协议中的所有实体主键、消息 ID 与版本 ID（`id`, `principal_id`, `space_id`, `object_id`, `revision_id`, `capability_id`, `invocation_id`, `receipt_id` 等）**MUST** 采用符合 [RFC 9562 §5.7](https://www.rfc-editor.org/rfc/rfc9562.html) 的小写 **UUIDv7 URN** 格式，其 ABNF（[RFC 5234](https://www.rfc-editor.org/rfc/rfc5234)）定义为：

```abnf
uuidv7-urn  = "urn:uuid:" 8HEXDIGL "-" 4HEXDIGL "-7" 3HEXDIGL "-" variant-hex 3HEXDIGL "-" 12HEXDIGL
variant-hex = "8" / "9" / "a" / "b"
HEXDIGL     = DIGIT / "a" / "b" / "c" / "d" / "e" / "f"
```

- 正则表达式：`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`。

### 2.2 密码学内容摘要（SHA-256 Digest）
所有内容摘要（`content_digest`, `base_digest`, `proposed_digest`, `expected_slice_digest`, `aad_digest`, `request_digest` 等）**MUST** 为 64 位小写十六进制 SHA-256 摘要并冠以 `"sha256:"` 前缀：

```abnf
sha256-digest = "sha256:" 64HEXDIGL
```

### 2.3 UTC 时间戳（RFC 3339 Timestamp）
所有协议时间戳（`occurred_at`, `issued_at`, `valid_from`, `valid_until`, `not_before`, `expires_at`, `revoked_at`, `effective_from`, `published_at`）**MUST** 采用符合 [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) 的 UTC 零时区格式（以大写 `"Z"` 结尾，支持秒或最多 6 位小数秒）：

```abnf
utc-timestamp = 4DIGIT "-" 2DIGIT "-" 2DIGIT "T" 2DIGIT ":" 2DIGIT ":" 2DIGIT ["." 1*6DIGIT] "Z"
```

### 2.4 可移植工作区相对路径（Portable Relative Path）
`wutong.object.payload.binding.relative_path` **MUST** 满足跨平台安全相对路径约束，严禁包含绝对路径根、盘符、`..`、`.`、空路径段、反斜杠 `\`、控制字符、尾随空格/句点或 Windows 保留设备名（`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`）。任何违规路径 **MUST** 以 `ERR_SYMLINK_OR_TRAVERSAL` 或 `ERR_SCHEMA` 拒绝。

## 3. 双线确定性编码规范（Dual Deterministic Wire Profiles）

Wutong Protocol 定义了两种严格一等公民且 **100% 双射（Bijective）** 的确定性线编码格式：

### 3.1 `application/wtp+json`（基于 RFC 8785 JCS 的确定性 JSON）
1. **字符编码**：**MUST** 为无 BOM 的严格 UTF-8（[RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)），严禁出现孤立代理项（Unpaired Surrogates `U+D800`..`U+DFFF`）。
2. **数值约束**：仅允许 `-(2^53 - 1)` 至 `+(2^53 - 1)`（即 `[-9007199254740991, 9007199254740991]`）范围内的精确十进制整数；**MUST NOT** 包含浮点数、`NaN`、`Infinity` 或前导零整数（如 `01`）。
3. **对象键约束**：所有 JSON 对象禁止出现重复键；在协议信封与荷载中，对象键名 **MUST** 为非空可打印 ASCII（`0x21..0x7E`）。
4. **规范化算法**：签名与摘要计算时，**MUST** 按照 [RFC 8785 JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785.html) 去除所有空白符，并按对象键名的 **UTF-16 码元序列（Code Unit Order）** 升序排列。

### 3.2 `application/wtp+cbor`（基于 RFC 8949 §4.2.1 的确定性 dCBOR）
1. **最短整数头编码（Shortest-Form Length/Integer Encoding）**：所有 CBOR 主类型（Major Types `0, 1, 3, 4, 5, 7`）的参数与长度 **MUST** 使用 [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html) 规定的最短字节表示（`< 24` 内联，`24..255` 1 字节，`256..65535` 2 字节，`65536..2^32-1` 4 字节，`>= 2^32` 8 字节）。解码器遇到非最短编码（如 `0x18 0x01` 表示整数 `1`）**MUST** 立即以 `ERR_SCHEMA` 拒绝（参见 [draft-ietf-cbor-cde](https://datatracker.ietf.org/doc/html/draft-ietf-cbor-cde-13)）。
2. **严禁不定长与原始字节串**：**MUST NOT** 使用不定长编码（`additional_info == 31` / `0xFF` break）、CBOR 标签（Major Type 6）、浮点数或原始字节串（Major Type 2）；二进制荷载统一表示为规范 Base64URL 文本串（Major Type 3），以保证 `application/wtp+cbor` 与 `application/wtp+json` 之间的无损双射。
3. **确定性 Map 键排序**：CBOR Map（Major Type 5）的所有键 **MUST** 按其 **CBOR 编码后字节序列的字典序（Bytewise Lexicographic Order of Encoded Key Bytes）** 严格升序排列（即先按 UTF-8 字节长度升序，同长度按 UTF-8 字节值升序），且严禁重复键。

### 3.3 跨网关转码签名保真（`proof.encoding`）
当联邦网关或中继节点在 `application/wtp+json` 与 `application/wtp+cbor` 之间转码已签名信封时，签名方可在 `proof.encoding` 中显式声明原始签名编码（`"jcs"` 或 `"dcbor"`）。验证方 **MUST** 根据 `proof.encoding`（若省略则按当前传输格式）选择对应的规范化器与域分离前缀进行验签，从而无需网关持有私钥重签名即可完成跨编码端到端验签。

## 4. 顶层信封结构（`WutongEnvelope`）与密码学签名

### 4.1 顶层信封结构
每条协议消息 **MUST** 是一个符合以下字段规范的顶层对象（`additionalProperties: false`）：

| 字段名 | 类型 | 必填 | 规范约束 |
|---|---|---|---|
| `protocol` | `string` | 是 | 固定常量 `"wutong/0.1"` |
| `kind` | `string` | 是 | 24 类规范消息枚举值之一（见第 5 节） |
| `id` | `uuidv7-urn` | 是 | 当前消息信封的全局唯一 UUIDv7 URN |
| `occurred_at` | `utc-timestamp` | 是 | 业务事件发生时间（UTC） |
| `payload` | `object` | 是 | 由 `kind` 决定的严格类型化荷载对象 |
| `extensions` | `object` | 否 | 反向域名格式的扩展命名空间字典（匹配 `^[a-z0-9]+(\.[a-z0-9_-]+)+\.[a-z0-9_-]+$`） |
| `critical` | `array<string>` | 否 | 接收方必须理解的关键扩展命名空间列表（非空唯一数组，且每项必须存在于 `extensions` 中） |
| `auth` | `object` | 签名必填 | `{signer_id, key_id, issued_at, nonce}`，与 `proof` 共存亡 |
| `proof` | `object` | 签名必填 | `{alg: "Ed25519", sig: "<base64url>", encoding?: "jcs" \| "dcbor"}`，与 `auth` 共存亡 |

### 4.2 关键扩展协商（Critical Extension Negotiation）
验证方在解析信封时：
1. 若 `critical` 数组中存在任何不在 `extensions` 键集合中的条目，**MUST** 以 `ERR_SCHEMA` 拒绝；
2. 若 `critical` 数组中包含当前实现未声明支持的扩展名，**MUST** 立即以 `ERR_VERSION` 拒绝（Fail-Closed）；
3. 未列入 `critical` 的 `extensions` 条目在纳入签名保护的同时，可被不识别该扩展的实现安全忽略。

### 4.3 域分离 Ed25519 签名与防延展性校验
1. **域分离签名输入（Signing Input）**：
   设移除顶层 `"proof"` 字段后的信封对象为 `E_unsigned`：
   - 当签名编码为 `"jcs"` 时：
     $$\text{SigningInput}_{\text{JCS}} = \text{ASCII}(\text{"WUTONG-SIG-V0.1"}) \parallel \text{0x00} \parallel \text{JCS}(E_{\text{unsigned}})$$
   - 当签名编码为 `"dcbor"` 时：
     $$\text{SigningInput}_{\text{dCBOR}} = \text{ASCII}(\text{"WUTONG-CBOR-SIG-V0.1"}) \parallel \text{0x00} \parallel \text{dCBOR}(E_{\text{unsigned}})$$
2. **严格 Ed25519 标量范围与弱公钥拦截**：
   - `proof.sig` 解码后 **MUST** 精确为 64 字节 `R (32B) || S (32B)`（且无填充 Base64URL 尾随零比特必须为 0）。
   - 验证器 **MUST** 将后 32 字节按小端序解析为整数 $S$，并强制验证 $0 \le S < L$，其中 $L = 2^{252} + 27742317777372353535851937790883648493$（[RFC 8032 §5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html)）。任何 $S \ge L$ 的签名 **MUST** 以 `ERR_SIGNATURE` 拒绝。
   - 公钥绑定或验签时，若 32 字节公钥属于全零或 Curve25519/Ed25519 低阶点集合，**MUST** 以 `ERR_KEY_UNBOUND` 拒绝。
3. **时间戳漂移与重放防护**：
   - 在任何模式下，`occurred_at` 与 `auth.issued_at` 之间的绝对偏差 **MUST NOT** 超过 `max_issuance_drift_seconds`（默认 300 秒），防止利用未来或远古 `occurred_at` 投毒业务时间线。
   - 在实时模式（`mode="live"`）下，$|t_{\text{now}} - \text{issued\_at}|$ **MUST NOT** 超过 `skew_seconds`（默认 300 秒），且 `(signer_id, nonce)` 与 `id` **MUST** 经由持久化重放账本（`DurableReplayLedger`）进行去重与双花分叉（Equivocation）检测。

## 5. 24 类规范消息荷载定义（Normative Message Registry）

以下定义 `urn:wutong:schema:core:0.1.2` 中的全部 **24 类规范消息**。每个 `payload` 对象均启用 `additionalProperties: false`，且可选支持扩展字段 `x`（类型为 JSON Object）。

| 序号 | `kind` | 所属 Profile | 必填 `payload` 字段 | 可选 `payload` 字段 | 核心规范语义 |
|---|---|---|---|---|---|
| 1 | `wutong.principal` | Core | `principal_id, principal_type` | `display_name, x` | 定义 `human`/`agent`/`organization`/`service`/`device` 五类一等主体 |
| 2 | `wutong.key_binding` | Security | `binding_id, principal_id, key_id, alg, public_key, purposes, valid_from, valid_until` | `previous_key_id, authority_id, x` | 绑定主体公钥：`alg="Ed25519"` 仅限签名/委托/认证/断言；`alg="X25519"` 仅限 `["encryption"]` |
| 3 | `wutong.revocation` | Security | `revocation_id, issuer_id, target_kind, target_id, revoked_at, effective_from, reason` | `x` | 撤销 `key_binding`、`capability` 或 `publication`；区分 `compromised` 与 `superseded` |
| 4 | `wutong.space` | Core | `space_id, owner_id, name, visibility` | `x` | 知识空间/Vault 容器（`local_only`/`private`/`shared`/`federated`/`public`） |
| 5 | `wutong.space_epoch` | Security | `epoch_id, space_id, epoch, key_id, issuer_id, sender_ephemeral_pub, space_x25519_pub, member_wraps` | `previous_epoch_digest, x` | 多成员 X25519 空间代次密钥封装与成员移除后向保密 |
| 6 | `wutong.object` | Core/Document | `object_id, space_id, owner_id, object_type, content_digest, media_type, byte_length` | `title, binding, x` | 知识对象元数据及原生文件绑定（`relative_path, line_ending, encoding`） |
| 7 | `wutong.revision` | Core | `revision_id, object_id, content_digest, parents, author_id` | `change_id, provenance, x` | 不可变版本 DAG 节点，`parents` 严禁自环或有向环 |
| 8 | `wutong.relation` | Core | `relation_id, source_id, target_ref, predicate, author_id` | `visibility, x` | 跨文档/跨空间类型化有向边（`references`, `derived_from` 等 7 类谓词） |
| 9 | `wutong.annotation` | Document | `annotation_id, target_ref, author_id, selector` | `target_revision, body_ref, visibility, x` | 支持 `TextQuote`、`TextPosition`、`BytePosition` 与 `Fragment` 的多重锚定批注 |
| 10 | `wutong.proposal` | Agent/Document | `proposal_id, object_id, proposer_id, base_digest, proposed_digest, intent, status` | `task_id, patches, provenance, x` | 变更提案；`intent="patch"` 时支持非重叠字节范围 `patches` 与 PROV-O `provenance` |
| 11 | `wutong.task` | Agent | `task_id, requester_id, state` | `assignee_id, target_ref, artifacts, idempotency_key, x` | 7 状态受控任务状态机（`created` → `assigned` → `accepted` → `running` → ...） |
| 12 | `wutong.capability` | Security/Agent | `capability_id, issuer_id, audience_id, resource_ref, actions, not_before, expires_at, delegable` | `parent_id, revocation_ref, x` | 细粒度能力授权与单调收窄委托令牌 |
| 13 | `wutong.event` | Core | `event_id, actor_id, action, subject_ref, result` | `causes, idempotency_key, x` | 不可篡改因果审计日志（`result`: `ok`/`denied`/`conflict`/`error`/`pending`） |
| 14 | `wutong.service` | Service | `service_id, space_id, owner_id, service_type, source_refs, spec_digest, visibility` | `x` | 知识即服务（KaaS）声明（`static_site`/`search_endpoint`/`qa_service` 等） |
| 15 | `wutong.publication` | Federation | `publication_id, object_id, revision_id, publisher_id, visibility, representation_digest, published_at` | `x` | 对外发布投射，与私有创作历史物理隔离 |
| 16 | `wutong.external_binding` | Interop | `binding_id, object_id, adapter_id, account_ref, remote_ref, direction` | `last_source_revision, origin_digest, x` | 外部平台适配器绑定，通过 `origin_digest` 阻断回声死循环 |
| 17 | `wutong.agent_manifest` | Agent | `agent_id, display_name, skills, input_types, output_types, execution` | `endpoint, x` | Agent 技能、输入输出类型与执行环境声明 |
| 18 | `wutong.artifact` | Agent | `artifact_id, task_id, creator_id, content_digest, media_type, byte_length` | `provenance, x` | 任务执行中间或最终产物信封，支持 PROV-O 溯源 |
| 19 | `wutong.sync_frame` | Sync | `session_id, space_id, step, seq` | `object_id, supported_codecs, selected_codec, heads, want, compacted_WaterMark_seq, chunk_digest, chunk_b64u, chunk_parents, presence_state, ttl_seconds, x` | 7 步同步帧（`HELLO`/`AUTH`/`SYNC_OFFER`/`SYNC_REQUEST`/`SYNC_CHUNK`/`SYNC_ACK`/`PRESENCE`） |
| 20 | `wutong.encrypted_envelope` | Security | `space_id, epoch, key_id, sender_ephemeral_pub, aead_alg, kdf_alg, nonce_b64u, inner_kind, aad_digest, ciphertext_b64u` | `x` | 空间级 E2EE 密文信封（`X25519-HKDF-SHA256` + `ChaCha20-Poly1305`） |
| 21 | `wutong.node_meta` | Federation | `node_id, operator_id, implementation, supported_profiles, supported_encodings, max_envelope_bytes, endpoints` | `x` | 联邦节点自描述能力清单与 7 个标准 HTTPS 端点路径 |
| 22 | `wutong.subscription` | Federation | `subscription_id, subscriber_id, target_ref, filter_kinds, delivery_mode, status, expires_at` | `cursor, x` | 跨节点事件流订阅契约（`webhook`/`sse`/`websocket`/`poll`） |
| 23 | `wutong.service_invocation` | Service/Federation | `invocation_id, service_id, action, caller_id, target_ref, capability_ids` | `arguments, idempotency_key, x` | **v0.1.2 新增**：受保护服务/RPC/联邦动作调用请求信封 |
| 24 | `wutong.receipt` | Federation/Service | `receipt_id, request_id, request_digest, responder_id, status` | `error_code, result_digest, applied_revision_id, retry_after_seconds, x` | **v0.1.2 新增**：带签名的执行回执与结构化错误响应信封 |

### 5.1 `wutong.service_invocation`（第 23 类）规范细则
- **必填字段**：
  - `invocation_id`（`uuidv7-urn`）：调用请求唯一标识；
  - `service_id`（`uuidv7-urn`）：目标 `wutong.service` 或联邦服务节点标识；
  - `action`（`action_name`）：请求的受保护操作名（如 `"document.propose"`, `"service.query"`）；
  - `caller_id`（`uuidv7-urn`）：调用主体 ID，**MUST** 精确等于外层 `auth.signer_id`；
  - `target_ref`（`uri_or_urn`）：目标资源 URN 或 URI；
  - `capability_ids`（`array<uuidv7-urn>`，1..16 项且唯一）：授权本次调用的能力令牌 ID 链。
- **可选字段**：`arguments`（JSON Object 调用参数）、`idempotency_key`（1..128 字符幂等键）。

### 5.2 `wutong.receipt`（第 24 类）规范细则
- **必填字段**：
  - `receipt_id`（`uuidv7-urn`）：回执唯一标识；
  - `request_id`（`uuidv7-urn`）：被响应的请求信封 `id`；
  - `request_digest`（`sha256-digest`）：被响应请求信封（不含 `proof`）的规范化 SHA-256 摘要，将回执与原始请求内容密码学绑定；
  - `responder_id`（`uuidv7-urn`）：响应节点或服务主体 ID，**MUST** 精确等于外层 `auth.signer_id`；
  - `status`（枚举）：`"accepted"` | `"completed"` | `"rejected"` | `"rate_limited"` | `"conflict"`。
- **条件约束**：
  - 当 `status` 为 `"rejected"`、`"rate_limited"` 或 `"conflict"` 时，可携带 16 类标准 `error_code` 及可选 `retry_after_seconds`（`1..86400`）；
  - 当 `status` 为 `"accepted"` 或 `"completed"` 时，**MUST NOT** 包含 `error_code`，可携带 `result_digest` 或 `applied_revision_id`。

## 6. 密码学密钥生命周期、撤销语义与多成员 E2EE 规范

### 6.1 密钥撤销原因区分与防回溯伪造（Compromise vs. Supersession）
`wutong.revocation` 的 `reason` 枚举为 `"compromised"` | `"superseded"` | `"affiliation_change"` | `"policy_violation"` | `"withdrawn"`：
1. 当 `reason != "compromised"`（例如常规轮换 `"superseded"`）时，在 `effective_from` 之前签发的历史签名在归档模式（`mode="archive"`）下继续有效（$\text{issued\_at} < \text{effective\_from}$）。
2. 当 `reason == "compromised"`（私钥失窃或泄露）时，攻击者完全有能力伪造任意早于 `effective_from` 的自报时间戳 `auth.issued_at`。因此，验证器 **MUST** 默认拒绝该失窃密钥在一切时间戳下的未公证签名（抛出 `ERR_KEY_REVOKED`），除非调用方提供由可信第三方或追加式透明日志在 `effective_from` 之前签发的独立公证证明（`notarized_before_revocation=True`）。

### 6.2 能力委托链验证与时序单调性（Capability Delegation Monotonicity）
给定能力委托链 $C_0 \to C_1 \to \dots \to C_k$（$0 \le k < 8$）：
1. 根能力 $C_0$ 的 `issuer_id` **MUST** 等于资源所有者 `root_owner`，末级能力 $C_k$ 的 `audience_id` **MUST** 等于执行者 `actor`。
2. 对于任意相邻父子能力 $(C_{i-1}, C_i)$：
   - $C_{i-1}.\text{delegable}$ **MUST** 为 `true`，且 $C_i.\text{issuer\_id} == C_{i-1}.\text{audience\_id}$；
   - $C_i.\text{resource\_ref} == C_{i-1}.\text{resource\_ref}$，且 $C_i.\text{actions} \subseteq C_{i-1}.\text{actions}$；
   - 有效期单调收窄：$C_{i-1}.\text{not\_before} \le C_i.\text{not\_before} < C_i.\text{expires\_at} \le C_{i-1}.\text{expires\_at}$；
   - **签发时间单调性（v0.1.2 强制）**：子能力的签发时间 $C_i.\text{auth.issued\_at}$ **MUST** 满足 $C_{i-1}.\text{auth.issued\_at} \le C_i.\text{auth.issued\_at}$ 且 $C_{i-1}.\text{not\_before} \le C_i.\text{auth.issued\_at} < C_{i-1}.\text{expires\_at}$。
3. 离线撤销新鲜度：若本地撤销快照时间戳缺失或 $|t_{\text{eval}} - t_{\text{freshness}}| > \text{max\_revocation\_staleness\_seconds}$，验证器 **MUST** 以 `ERR_REVOCATION_STALE` 失败关闭（Fail-Closed）。

### 6.3 多成员空间代次密钥封装（`wutong.space_epoch`）与信封加密（`wutong.encrypted_envelope`）
1. **代次密钥分发（`wutong.space_epoch`）**：
   - 管理员为空间代次 `(space_id, epoch, key_id)` 生成 32 字节 `epoch_secret` 与 32 字节 `space_x25519_seed`（对应公钥 `space_x25519_pub`）。
   - 对每位授权成员 $(M_j, K_j)$，使用发送方临时 X25519 私钥与成员已绑定的 X25519 公钥计算 ECDH 共享密钥（全零共享密钥 **MUST** 拒绝），并以 `AAD_wrap = UTF8("WUTONG-EPOCH-WRAP-V0.1|" + space_id + "|" + epoch + "|" + key_id + "|" + M_j + "|" + K_j)` 经 [RFC 5869 HKDF-SHA256](https://www.rfc-editor.org/info/rfc5869) 派生 32 字节封装密钥，用 [RFC 8439 ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439) 加密 64 字节 `epoch_secret || space_x25519_seed`。
2. **Verify-Then-Decrypt 空间密文信封（`wutong.encrypted_envelope`）**：
   - 内部信封先由作者签名，再使用 `IKM = X25519(sender_eph_priv, space_x25519_pub) || epoch_secret` 与 `AAD = JCS({space_id, epoch, key_id, sender_ephemeral_pub, aead_alg, kdf_alg, nonce_b64u, inner_kind})` 加密，外层信封再次由发送方签名。
   - 接收方 **MUST** 先校验外层 Ed25519 签名与 `aad_digest`，通过后方可调用 AEAD 解密，最后校验内层作者签名。

## 7. `WTP-Sync` 同步状态机与瞬态 Presence 规范

1. **状态转移顺序**：`HELLO` → `AUTH` → `SYNC_OFFER` → (`SYNC_REQUEST` → `SYNC_CHUNK`*) → `SYNC_ACK`，并在会话建立后允许发送瞬态 `PRESENCE` 帧。
2. **传递性因果闭包与快照回退**：
   - `SYNC_OFFER.heads` 传递拓扑排序的传递性因果闭包摘要列表，`SYNC_CHUNK` 携带 `chunk_parents` 并在写入前校验 SHA-256 摘要与 `max_chunk_bytes`（默认 512 KiB）。
   - 当对端已知序号 `peer_known_seq < compacted_watermark_seq` 时，`AUTH` 阶段 **MUST** 自动回退选择 `"snapshot/1"` 编解码器；若双方不支持 `"snapshot/1"`，**MUST** 返回 `ERR_UNSUPPORTED`。
3. **瞬态 Presence 隔离（v0.1.2）**：
   - `step == "PRESENCE"` 的 `wutong.sync_frame` **MUST** 包含 `presence_state`（`"online"` | `"typing"` | `"viewing"` | `"idle"`）与 `ttl_seconds`（`1..60`），且 **MUST NOT** 携带 `chunk_b64u` 或修改持久化 `RevisionDAG`。

## 8. `WTP-Federation` 与 `WTP-Service` HTTPS 绑定规范

所有联邦与远程服务节点 **MUST** 仅通过 `https://` 暴露以下 7 个标准端点（禁止明文 HTTP、URL 内嵌凭据及私网/环回/CGNAT/链路本地/云元数据 IP，违者触发 `ERR_SSRF_BLOCKED`），且所有 POST 请求 **MUST** 校验 [RFC 9530 `Content-Digest: sha-256=:<base64>:`](https://www.rfc-editor.org/rfc/rfc9530.html)：

| 路径 | HTTP 方法 | 请求信封类型 | 响应信封/结构 |
|---|---|---|---|
| `/_wutong/v0.1/meta` | `GET` | 无 | 已签名 `wutong.node_meta` 信封 |
| `/_wutong/v0.1/objects` | `POST` | 已签名 `wutong.object` 或 `wutong.publication` | 已签名 `wutong.receipt` 信封 |
| `/_wutong/v0.1/revisions` | `POST` | 已签名 `wutong.revision` | 已签名 `wutong.receipt` 信封 |
| `/_wutong/v0.1/resolve` | `GET` | 查询参数 `?ref=<urn-or-uri>` | 目标已签名信封（若已撤回则返回 404 `ERR_UNRESOLVED`） |
| `/_wutong/v0.1/subscriptions` | `POST` / `GET` | `POST`: 已签名 `wutong.subscription`；`GET`: `?subscription_id=...&cursor=...&limit=1..256` | `POST`: 已签名 `wutong.subscription`；`GET`: `{subscription_id, next_cursor, has_more, events}` |
| `/_wutong/v0.1/invocations` | `POST` | `{invocation: wutong.service_invocation, capabilities: [wutong.capability, ...]}` | 已签名 `wutong.receipt` 信封 |
| `/_wutong/v0.1/sync` | `POST` | 已签名 `wutong.sync_frame` | 已签名应答 `wutong.sync_frame` |

## 9. 16 类规范错误码注册表（Normative Error Code Registry）

| 错误码 | HTTP 状态码 | 规范触发条件 |
|---|---|---|
| `ERR_SCHEMA` | `400 Bad Request` | JSON/dCBOR 语法错误、非最短 CBOR 整数、原始 CBOR 字节串、乱序/重复键、浮点数或 Schema 校验失败 |
| `ERR_VERSION` | `400 Bad Request` | 不支持的 `protocol` 版本或包含未受支持的 `critical` 关键扩展命名空间 |
| `ERR_SIGNATURE` | `401 Unauthorized` | Ed25519 验签失败、标量 $S \ge L$、HTTP `Content-Digest` 不匹配、时间戳漂移超限 |
| `ERR_KEY_UNBOUND` | `401 Unauthorized` | 公钥未绑定、超出有效期、用途不匹配或属于全零/低阶弱公钥 |
| `ERR_KEY_REVOKED` | `401 Unauthorized` | 密钥已被 `wutong.revocation` 撤销（含 `reason="compromised"` 的全时段未公证签名拦截） |
| `ERR_REVOCATION_STALE` | `503 Service Unavailable` | 离线撤销状态快照缺失或超出新鲜度预算（Fail-Closed） |
| `ERR_PERMISSION` | `403 Forbidden` | Capability 委托链验证失败、子能力签发时间违背单调性、越权或 Provenance 自提自审 |
| `ERR_REPLAY` | `409 Conflict` | `(signer_id, nonce)` 已被消费且非合法的幂等重试 |
| `ERR_EQUIVOCATION` | `409 Conflict` | 同一 `id` 或 `(signer_id, nonce)` 对应不同的规范化消息摘要（双花/分叉攻击） |
| `ERR_DECRYPTION_FAILED` | `400 Bad Request` | `wutong.space_epoch` 未包含当前成员、X25519 全零共享密钥、`aad_digest` 不匹配或 AEAD 校验失败 |
| `ERR_CONFLICT` | `409 Conflict` | 原生文件基线/切片哈希不匹配、补丁重叠、`RevisionDAG` 环路或外部同步回声死循环 |
| `ERR_SYMLINK_OR_TRAVERSAL` | `400 Bad Request` | 相对路径违规或 OS `O_NOFOLLOW`/`fstatat` 检测到符号链接/工作区逃逸 |
| `ERR_SSRF_BLOCKED` | `403 Forbidden` | 联邦端点非 HTTPS、含内嵌凭据或解析至环回/私网/链路本地/CGNAT/云元数据 IP |
| `ERR_UNRESOLVED` | `404 Not Found` | 请求的对象、版本、父节点、订阅不存在，或 `wutong.publication` 已被撤回 |
| `ERR_RATE_LIMIT` | `429 Too Many Requests` | 调用主体超出节点或适配器速率配额 |
| `ERR_UNSUPPORTED` | `501 Not Implemented` | 同步编解码器无交集、压缩水位线落后且无 `snapshot/1`、或未知批注选择器 |
