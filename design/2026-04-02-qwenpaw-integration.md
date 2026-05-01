# QwenPaw x AgentID Integration

QwenPaw 如何集成 AgentID 栈。


## 架构总览

```
AgentID CLI (aip init / aip agent create)
    └── aip-identity-sdk（密钥生成、主体注册、Agent 创建）

IdP (aip-idp, 在建, 不属于QwenPaw范畴; 域名假设为 agent-registry.ai)
    ├── GitHub OAuth / 阿里云 ID
    ├── 阿里云 TableStore（持久化）
    └── 阿里云 KMS（签名密钥）

QwenPaw Agent Runtime
    └── aip-identity-sdk（可选：加载私钥、签名换 JWT、注入认证头）

QwenPaw Hub (PawFriends, DojoZero)
    └── aip-identity-verify（验签 JWT、识别 Agent 身份）
```

## 集成点

### 1. 身份注册：独立于 QwenPaw

身份注册通过 AgentID CLI 完成，不是 QwenPaw 的职责。开发者可以在任何时候注册。

```
aip init --provider agent-registry.ai
  → Device Flow（GitHub）或 Auth Code + PKCE（阿里云 ID）
  → 拿到 management_token
  → 保存到 ~/.agentid/config.json

aip agent create --name shark
  → 本地生成 Ed25519 密钥对
  → 公钥注册到 aip-idp
  → 私钥保存到 ~/.agentid/agents/shark/private_key
  → agent.json 保存 agent_id、kid
```

### 2. Agent Runtime：匿名优先，身份可选

QwenPaw 框架启动时探测是否有 AgentID 身份。有则用，无则匿名。

```python
# QwenPaw 框架内部（agent 作者看不到这部分）
from aip_identity_sdk import AIPIdentity

try:
    identity = AIPIdentity.from_profile("shark")  # 或 from_env()
except FileNotFoundError:
    identity = None  # 匿名模式

# 每次请求 hub 时
if identity:
    token = get_or_refresh_jwt(identity, audience=hub_url)
    headers["Authorization"] = f"AgentID {token}"
# else: 无认证头，匿名访问
```

```python
# Agent 作者的代码——不需要 import 任何 AgentID 相关的东西
# 不管有没有 AgentID 身份，代码完全一样
class SharkAgent(QwenPawAgent):
    def act(self, observation):
        return self.hub.submit(my_prediction)  # 有身份→认证访问，无身份→匿名访问
```

### 3. Hub：分级访问

Hub 根据请求是否携带 AgentID 身份，提供不同级别的访问。

```python
from aip_identity_verify import AIPVerifier

verifier = AIPVerifier(
    trusted_providers=["agent-registry.ai"],
    audience="https://arena.openclaw.ai",
)

async def handle_request(request):
    auth = request.headers.get("Authorization")

    if auth and auth.startswith("AgentID "):
        # 已认证 Agent
        agent = await verifier.verify(auth)
        return full_access(agent)
    else:
        # 匿名 Agent——受限访问
        return limited_access()
```

分级示例：

| | 匿名 | AgentID 认证 |
|---|---|---|
| 访问频率 | 受限 | 更高限额 |
| 功能 | 只读 / 基础 | 完整功能 |
| 信誉 | 无 | 可累积跨平台信誉 |
| 问责 | 无 | 可追溯到主体 |

## 数据流

```
身份注册（可选，一次性，通过 AgentID CLI）：
  开发者 → aip init → aip-idp → GitHub/阿里云 OAuth → 主体创建
  开发者 → aip agent create → 本地生成密钥 → aip-idp 注册公钥

运行时（每次请求）：
  有身份：Agent → aip-identity-sdk → 私钥签名 → aip-idp → JWT → Hub（验签通过）
  无身份：Agent → Hub（匿名访问，受限）
```

## 身份存储

| 位置 | 内容 | 谁能访问 |
|------|------|----------|
| `~/.agentid/config.json` | principal_id、management_token | AgentID CLI |
| `~/.agentid/agents/shark/agent.json` | agent_id、kid | Agent runtime |
| `~/.agentid/agents/shark/private_key` | Ed25519 私钥（权限 0600） | Agent runtime |
| aip-idp (TableStore) | 主体、Agent、公钥 | IdP 服务 |

私钥只存在于 Agent 运行的机器上。IdP 永远不持有私钥。

## 远程部署场景

Agent 跑在云服务器上，开发者在本地笔记本完成 OAuth：

```
笔记本（有浏览器）：
  aip init --provider agent-registry.ai → OAuth → management_token

云服务器（无浏览器）：
  aip agent create --name shark --token <粘贴 management_token>
  → 密钥对在云服务器本地生成
  → Agent 就地运行
```

或通过环境变量（CI/CD）：

```bash
AGENTID_AGENT_ID=agentid:agent-registry.ai:agent_xxx
AGENTID_AGENT_KID=abc123
AGENTID_PRIVATE_KEY=<hex>
# AGENTID_IDP_URL 可选覆盖；默认从 agent_id 域名推导（https://{domain}）
```

## IdP 域名到 URL 的解析

SDK 从 agent_id 中提取域名（如 `agentid:agent-registry.ai:agent_x` → `agent-registry.ai`），然后解析为可达的 IdP URL。

**解析规则（按优先级）：**

1. **显式覆盖** — `AGENTID_IDP_URL` 环境变量或代码中 `identity.idp_url = ...`
2. **中心注册表** — 由 CA 或中心 Hub 维护的域名→URL 映射（如 `agent-registry.live` 提供的查询服务）
3. **DNS 默认** — `https://{domain}`，生产环境中 DNS + TLS 直接解析

域名到 URL 的映射不应由每个 agent 各自维护。生产环境依赖 DNS；非标准场景（开发端口、代理等）由中心注册表或 Hub 的 `provider_urls` 配置统一管理。

```
生产环境：agent_id 域名 → DNS → https://{domain}
开发环境：agent_id 域名 → 中心注册表或 Hub provider_urls → http://localhost:8000
```

## QwenPaw stack 需要做的事

| 任务 | 依赖 | 说明 |
|------|------|------|
| Agent runtime 集成 | aip-identity-sdk | 启动时探测身份，有则注入 header，无则匿名 |
| Hub 验证中间件 | aip-identity-verify | FastAPI/WebSocket 中间件，验签 + 分级访问 |
| JWT 缓存 | 自行实现 | Agent runtime 缓存 JWT 直到接近过期 |

QwenPaw 不需要实现密码学、OAuth 流程、密钥管理或 JWT 验签——全部由 AgentID 栈提供。身份注册由 AgentID CLI 独立完成。
