# Wutong Protocol（梧桐协议）v0.1.2 发布演进与多语言工程实现指南

> **文档编号**：WTP-DOC-03  
> **文档类型**：正式发布演进与多语言工程实现指南（Release & Multi-Language Implementation Guide）  
> **适用版本**：`Wutong Protocol v0.1.2`（`urn:wutong:schema:core:0.1.2`）  
> **发布日期**：2026-10-18  
> **许可证**：[GNU AGPL v3.0 only](https://spdx.org/licenses/AGPL-3.0-only.html)（`SPDX-License-Identifier: AGPL-3.0-only`）

## 1. 从 `v0.1-rc.1` 到 `v0.1.2` 正式版五阶段演进总览

| 版本阶段 | 规范消息数 | 关键工程与协议突破 |
|---|---|---|
| **`v0.1-rc.1`**（初始候选） | 15 类 | 定义基础 JSON 信封、15 类核心消息与 C++23 本地 SQLite 原型 |
| **`v0.1-rc.2`**（第一轮完善） | 17 类 | 新增 `wutong.key_binding` 与 `wutong.revocation`；修正 [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) UTF-16 码元排序；补齐 C++23 `WriteIntent` 三阶段崩溃自愈与 `DurableReplayLedger` |
| **`v0.1.0`**（第二轮完善） | 21 类 | 新增 `wutong.sync_frame`, `wutong.encrypted_envelope`, `wutong.node_meta`, `wutong.subscription`；补齐 [RFC 8949 §4.2.1 `dCBOR`](https://www.rfc-editor.org/rfc/rfc8949.html) 编码器与 [OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0.html) 规范 |
| **`v0.1.1`**（第三轮完善） | 22 类 | 新增第 22 类 `wutong.space_epoch` 多成员 X25519 密钥分发；实现 Source-First 字节范围补丁 `patches` 与 [W3C PROV-O](https://www.w3.org/TR/prov-o/) `provenance`；支持跨网关 `proof.encoding` 透传与 [RFC 8032 §5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html) 严格标量校验 |
| **`v0.1.2`**（正式标准定稿） | **24 类** | **新增第 23 类 `wutong.service_invocation` 与第 24 类 `wutong.receipt` 实现请求/回执全闭环；新增密钥失窃（`compromised`）回溯伪造拦截与委托链签发时间单调性校验；补齐 C++23 原生二进制 `dCBOR` 解码器与直接验签器；实现瞬态 `PRESENCE` 同步帧隔离** |

## 2. `wutong-protocol-v0.1.2` 工程包目录结构与模块职责

```text
wutong-protocol-v0.1.2/
├── LICENSE                                  # GNU AGPL v3.0 only 官方完整许可正文（33,913 字节）
├── THIRD_PARTY_NOTICES.md                   # 第三方运行时/工具链许可证兼容性清单
├── generate.py                              # 24 类 Schema、示例、测试向量与 OpenAPI 3.1.0 生成器
├── schemas/
│   ├── core.schema.json                     # JSON Schema Draft 2020-12（urn:wutong:schema:core:0.1.2，24 类）
│   └── registry.json                        # 24 类规范消息元数据与 16 类标准错误码注册表
├── openapi/
│   └── wutong-federation-v0.1.openapi.json  # OpenAPI 3.1.0 联邦与服务 7 端点规范（version: 0.1.2）
├── examples/                                # 24 个通过严格 JSON 与 Schema 校验的规范消息实例
├── vectors/                                 # 跨语言固定种子 Ed25519 公钥、JCS 与签名测试向量
├── src/wtp/
│   ├── wire.py                              # 严格 JSON 解析、RFC 8785 UTF-16 JCS、RFC 8032 Ed25519 验签
│   ├── cbor_wire.py                         # RFC 8949 §4.2.1 确定性 dCBOR 编解码器与 CBOR 签名验签
│   ├── policy.py                            # KeyRegistry（区分 compromised 与 superseded）与时序单调委托链
│   ├── e2ee.py                              # SpaceEpochKeyring 多成员 X25519 封装与 ChaCha20-Poly1305
│   ├── sync.py                              # SyncReplica 传递性因果闭包、快照回退与瞬态 PRESENCE 帧
│   ├── federation.py                        # FederationNode（返回签名 wutong.receipt）、SSRF 拦截、DAG、重锚定
│   ├── document_patch.py                    # apply_source_patches 字节范围补丁与 W3C PROV-O 校验
│   ├── filecoord.py                         # POSIX O_NOFOLLOW + fstatat + SQLite WAL 双相崩溃自愈协调器
│   ├── replay.py                            # SQLite WAL+FULL 持久化防重放与双花分叉检测账本
│   ├── semantic.py                          # 24 类消息跨字段语义与安全相对路径校验器
│   └── testshim.py                          # 零外部依赖单元测试运行器（兼容 pytest 语法）
├── tools/
│   ├── jcs_node.cjs                         # Node.js RFC 8785 UTF-16 JCS 对照验证器
│   ├── dcbor_node.cjs                       # Node.js RFC 8949 dCBOR 编解码与 Ed25519 对照验证器
│   └── run_conformance.sh                   # 一键执行三语言合规测试与 C++23 ASan/UBSan 内存安全验证
└── reference/                               # C++23 离线核心、JCS、原生二进制 dCBOR 编解码与 OpenSSL 验签引擎
    ├── include/wutong/core.hpp              # C++23 公共 API 头文件
    ├── include/wutong/sqlite3_compat.hpp    # 免系统开发包依赖的最小 SQLite3 ABI 兼容头
    ├── src/core.cpp                         # C++23 Store、WriteIntent 恢复、JCS、原生 dCBOR 编解码与验签
    ├── tools/digest.cpp                     # C++23 SHA-256 命令行工具
    ├── tools/verify_wire.cpp                # C++23 JCS / dCBOR 编解码与 JSON/CBOR 信封验签 CLI
    └── tests/                               # C++23 test_core.cpp、test_crosslang.py、test_schema.py
```

## 3. 多语言工程实现关键细则

### 3.1 C++23 原生二进制 `dCBOR` 解码器与直接验签器（`reference/src/core.cpp`）
在 `v0.1.2` 中，C++23 引擎新增了无需外部 JSON 预转换的 `DcborDecoder`（`wutong::dcbor_to_jcs`、`wutong::dcbor_hex_to_jcs` 与 `wutong::verify_raw_cbor_hex_envelope`）：
1. **最短整数头校验**：在 `read_head()` 中严格检查 `ai == 24`（要求 `val >= 24`）、`ai == 25`（要求 `val > 0xFF`）、`ai == 26`（要求 `val > 0xFFFF`）、`ai == 27`（要求 `val > 0xFFFFFFFFULL`），任何非最短整数头或 `ai == 31` 不定长编码立即抛出 `ERR_SCHEMA`。
2. **CBOR Map 键序字节级校验**：解码每个 Map（Major Type 5）条目时，记录键的原始 CBOR 字节切片 `[k_start, k_end)`，强制校验 `cur_key_bytes > prev_key_bytes`，直接拦截乱序键或重复键。
3. **直接二进制验签**：`verify_raw_cbor_hex_envelope` 直接从原始 CBOR 字节流解码信封，提取并校验 `proof.sig`（含 `0 <= S < L` 标量检查与弱公钥过滤），移除 `"proof"` 后重新序列化为规范 `dCBOR` 并拼接 `"WUTONG-CBOR-SIG-V0.1\0"` 调用 OpenSSL `EVP_DigestVerify` 完成验签。

### 3.2 `KeyRegistry` 密钥泄露回溯防御与委托时序单调性（`src/wtp/policy.py`）
1. **密钥失窃（`compromised`）vs 常规轮换（`superseded`）**：
   ```python
   if rev["reason"] == "compromised" and not notarized_before_revocation:
       return True
   if rev["effective_from"] <= at_dt:
       return True
   ```
   当密钥因 `superseded` 轮换时，早于 `effective_from` 的历史归档签名正常通过；当密钥因 `compromised` 撤销时，除非调用方传入经独立透明日志/时间戳机构公证的 `notarized_before_revocation=True`，否则一切自报历史时间戳均被视为不可信并抛出 `ERR_KEY_REVOKED`。
2. **能力委托链签发时间单调性**：
   在 `authorize_chain` 中，除校验权限子集与 `[nbf, exp]` 区间收敛外，强制要求子能力的 `auth.issued_at` 满足：
   ```python
   if c_iat < p_iat or not (parse_time(parent["nbf"]) <= c_iat < parse_time(parent["exp"])):
       break
   ```
   从而阻断中间代理人在父能力尚未生效或已过期时违规预签发/倒填子能力。

### 3.3 受保护调用与带签名回执闭环（`src/wtp/federation.py`）
`FederationNode.invoke_protected_action` 接收已签名的 `wutong.service_invocation` 信封：
1. 校验调用者速率配额（`_check_rate_limit`）、Ed25519 签名、持久化防重放账本（`DurableReplayLedger`）以及 `caller_id == auth.signer_id`；
2. 调用 `authorize_signed_capability_chain` 验证随附的 `wutong.capability` 委托链及离线撤销新鲜度；
3. 计算请求信封（去 `proof`）的规范化摘要 `request_digest`，构造并由节点算子签名返回 `wutong.receipt` 信封（`status="accepted"`）。

## 4. 一键可重复构建与验证指令

在工程包根目录下执行以下命令即可完成 Schema/向量生成、Python 3.11 + Node.js 18 测试、C++23 编译测试及 ASan + UBSan 内存消毒验证：

```bash
python3 generate.py
bash tools/run_conformance.sh
```
