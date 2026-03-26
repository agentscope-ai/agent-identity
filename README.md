# Agent Identity Protocol (AIP)

**给 AI Agent 一张全网通用的身份证。**

AIP 是一个开放协议，为 AI Agent 提供跨平台的身份认证、活动追踪和信任体系。不是某家公司的产品，而是一个任何人都能实现的标准——就像 OIDC 改变了"用 Google 登录"，AIP 要让 Agent 身份成为基础设施。

---

## 为什么需要 AIP？

今天的 AI Agent 是"黑户"。你的 Agent 在 DojoZero 上赢了100场，换个平台？没人认识你，战绩清零，从头开始。

每个平台各搞一套账号体系——API Key、邮箱注册、推文验证……Agent 用十个平台就得管十套凭证。

人类早就解决了这个问题：Single Sign on, "用 Google 登录"——一个身份，到处通用。Agent 还没有。

---

## 核心设计

### 一把密钥就是你的身份

Agent 生成一对 Ed25519 密钥。私钥自己留着，永远不出本地环境。公钥注册到身份提供商（IdP）。就像把 SSH 公钥放到 GitHub 上。

每个 Agent 有一个全局唯一的 ID：

```
aip:<提供商域名>:<唯一标识>

例：aip:copaw.ai:agent_7x8k2m
    aip:identity.alibaba.com:agent_3p9n2q
```

### 认证流程

```
Agent                          IdP                           平台 (Hub)
  │                             │                               │
  │  1. 用私钥签名请求           │                               │
  │  ──────────────────────────>│                               │
  │                             │                               │
  │  2. IdP 验证签名，           │                               │
  │     签发短期 JWT (1-4小时)   │                               │
  │  <──────────────────────────│                               │
  │                             │                               │
  │  3. 带着 JWT 访问平台        │                               │
  │  ──────────────────────────────────────────────────────────>│
  │                             │                               │
  │                             │  4. 平台用 IdP 公钥本地验签     │
  │                             │     (不用回调 IdP)             │
  │                             │                               │
  │  5. 正常响应                 │                               │
  │  <──────────────────────────────────────────────────────────│
```

平台验签是**本地完成**的——提前缓存 IdP 公钥，验签只是一个本地计算。IdP 挂了不影响已签发 token 的验证。

### JWT 内容

```json
{
  "iss": "https://copaw.ai",
  "sub": "aip:copaw.ai:agent_7x8k2m",
  "aud": "https://dojozero.example.com",
  "exp": 1711328400,
  "aip_version": "1.0",
  "agent_name": "shark",
  "principal": { "type": "org", "id": "org_acme", "name": "Acme Corp" }
}
```

- `aud` 必填——token 锁定到特定平台，防止冒用
- `exp` 有效期短——泄露了损失窗口也有限
- `principal` 标明谁负责——个人开发者或组织

---

## 协议分层

```
┌─────────────────────────────────────────┐
│  Layer 3: 信任与声誉                      │  信任评分、跨平台分析
├─────────────────────────────────────────┤
│  Layer 2: 活动证明                        │  平台签名的活动报告
├─────────────────────────────────────────┤
│  Layer 1: 授权与声明                      │  能力、范围、合规
├─────────────────────────────────────────┤
│  Layer 0: 密码学身份                      │  密钥、Token、认证
└─────────────────────────────────────────┘
```

每层独立，可以逐层采用。最小可用集是 Layer 0。

---

## 关键特性

### 联邦制：谁都能开 IdP

任何人都能运行一个 IdP，只要实现标准端点：

| 端点 | 用途 |
|------|------|
| `/.well-known/aip-configuration` | 服务发现 |
| `/.well-known/aip-jwks` | IdP 公钥（JWKS 格式） |
| `/aip/agents` | 注册新 Agent |
| `/aip/token` | 私钥签名换 JWT |
| `/aip/activity` | 接收/查询活动记录 |

平台看 JWT 里的 `iss` 字段，去对应域名拿公钥验签。跟浏览器验 HTTPS 证书一个道理。

### 密钥可移植

密钥属于 Agent，不属于 IdP。同一把公钥可以注册到多个提供商：

```
                    ┌─── CoPaw    → aip:copaw.ai:agent_abc
                    │
Agent（一把密钥）   ├─── GitHub   → aip:github.com:agent_xyz
                    │
                    └─── 直接注册到平台（本地模式）
```

要证明多个身份是同一个 Agent？用共享私钥签一个 linkage 声明，任何人都能验证。

### 本地模式：万能兜底

平台不认你的 IdP？直接把公钥注册上去——就像 SSH `authorized_keys`。没有 IdP 参与，平台直接验签名。

代价：身份不能跨平台携带，没有信誉积累。但用的是同一把钥匙，以后随时升级到完整 AIP。

### 信任计划

为避免碎片化（每个平台自己决定信任谁），AIP 维护一份经审核的可信 IdP 名单——类似浏览器的 CA 根证书列表。平台拿来当默认配置，也可以自行增减。

### 双向认证

不只是平台验 Agent——Agent 也要验平台。出示 token 之前，Agent 应确认平台的 TLS 证书和 `service_id` 与 token 的 `aud` 一致，防止把 token 交给假平台。

### Agent 间认证

两个来自不同 IdP 的 Agent 也能互验身份——各自读对方 JWT 的 `iss`，去对应 IdP 拿公钥验签。没有中央权威，各自维护自己的可信提供商列表。

---

## 活动追踪

平台上报 Agent 的活动记录，由**平台签名**——不是 Agent 自己说的：

```json
{
  "agent_id": "aip:copaw.ai:agent_7x8k2m",
  "service_id": "https://dojozero.example.com",
  "activity_type": "prediction_market",
  "summary": { "games_played": 3, "pnl": 150.0 },
  "outcome": "completed",
  "service_signature": "<平台私钥签名>"
}
```

活动追踪器与 IdP 分开运行。IdP 管"你是谁"（小而稳），活动追踪器管"你做过什么"（大流量，独立扩展）。

**互惠机制**：平台想查 Agent 信用？先贡献自己的活动数据。不贡献就查不了。

**隐私控制**：主体可以选择上报粒度——完整细节、汇总、仅存在性、或完全不报。

Agent 也可以查自己的历史记录：

```
GET /aip/activity/{agent_id}?last=30d
Authorization: AIP <自己的 token>
```

---

## 问责模型

每个 Agent 背后有一个**主体（Principal）**：

- **个人主体**——开发者，通过 GitHub OAuth 等验证
- **组织主体**——公司/团队，通过域名验证。人来人走，Agent 不受影响

问责链条：`动作 → Agent → 主体（人或组织）→ 司法管辖区`。总有人兜底。

---

## 项目结构

```
design/
  ├── 2026-03-11-agent-identity.md              # 初始设计思考
  ├── 2026-03-25-agent-identity-protocol.en.md   # AIP 协议规格（英文）
  ├── 2026-03-25-agent-identity-protocol.zh.md   # AIP 协议规格（中文）
  └── 2026-03-25-agent-identity-commercialization.md  # 商业化策略
```

---

## 状态

**Draft** — 协议规格设计中。Layer 0 基本就绪，征求反馈。

---

## 相关工作

- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/) — 微软的企业 Agent 身份方案。锁定 M365 生态，不是开放标准，但验证了问题空间的价值。
- [Ping Identity for AI](https://www.pingidentity.com/en/solution/agentic-ai-identity.html) — 基于 OAuth 2.0 Token Exchange 的企业 Agent 身份管控。重治理和 MCP 集成，但身份归平台所有，不解决跨平台可移植性。
- [IETF WIMSE](https://datatracker.ietf.org/group/wimse/about/) / [SPIFFE](https://spiffe.io/) — 工作负载身份标准，正在被拉伸用于 Agent 场景。AIP Layer 0 可插拔兼容。
- [OAuth 2.0](https://oauth.net/2/) / [OIDC](https://openid.net/connect/) — AIP 借鉴了联邦身份认证的成熟模式，但为 Agent 做了原生设计。
- [NIST NCCoE AI Agent Identity](https://www.nccoe.nist.gov/agentic-ai-identity-and-access-management) — NIST 关于 Agent 身份的概念文件，征求意见中（2026年4月2日截止）。
