# Wutong Protocol · 梧桐协议

[![CI](https://github.com/project-wutong/wutong-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/project-wutong/wutong-protocol/actions/workflows/ci.yml)
`wutong/0.1` · spec revision **v0.1.2** (`WTP-STD-001`) · schema `urn:wutong:schema:core:0.1.2` · License `AGPL-3.0-only`

## 中文

梧桐协议（WTP）是面向**本地优先原生内容、知识对象、Agent 原生身份与贡献、权限化协作、开放联邦与知识服务化**
的可扩展协议。本仓库是协议的**规范来源（source of truth）**：

| 路径 | 内容 |
|---|---|
| `docs/` | 四份正式文档：总体架构 v1.4、正式标准规范 WTP-STD-001、发布与实现指南、一致性与审计报告 |
| `spec/` | 规范正文、发布门禁、Rust 实现蓝图、安全评审；`spec/history/` 保存 v0.1.0-rc.1 原始候选规范 |
| `schemas/` | JSON Schema Draft 2020-12（24 类规范消息）与机器可读 Registry |
| `openapi/` | 联邦与服务 HTTPS 绑定（OpenAPI 3.1.0） |
| `examples/` | 24 个规范消息样例 |
| `vectors/` | 跨语言固定测试向量（JCS、dCBOR、SHA-256、Ed25519、E2EE），`vectors/crosslang/` 供 Rust/SDK 使用 |
| `src/wtp/`, `tests/` | Python 参考实现与 143 项协议测试 |
| `tools/` | Node.js 对照实现、生成器、一键一致性脚本 |
| `reference/` | 先前的 C++23 参考核心（作为独立一致性实现保留） |
| `wip/` | WIP（梧桐改进提案）流程 |

```bash
pip install -r requirements-dev.txt
bash tools/run_conformance.sh
```

> ⚠️ 成熟度：Core/Document/Agent 为候选；Security/Sync/Federation/Service/Interop 为**实验性**且未经第三方审计。
> 本仓库的生产级实现请见 Rust 核心 [`wutong-core`](https://github.com/project-wutong/wutong-core)。

## English

The Wutong Protocol is an extensible protocol for local-first native content, knowledge objects,
agent-native identity, permissioned collaboration, open federation and knowledge-as-a-service.
This repository is the normative source: formal spec, schemas, registry, OpenAPI binding,
examples, golden vectors and the Python/Node/C++ reference conformance kit.
The independent Rust implementation lives in [`wutong-core`](https://github.com/project-wutong/wutong-core).
