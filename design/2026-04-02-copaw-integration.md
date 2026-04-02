# CoPaw x AIP Integration

CoPaw 如何集成 Agent Identity Protocol 栈。

## 架构总览

```
CoPaw CLI (copaw init / copaw agent create)
    └── aip-identity-sdk（密钥生成、主体注册、Agent 创建）

CoPaw IdP (aip-idp 部署)
    ├── GitHub OAuth + 阿里云 ID
    ├── 阿里云 TableStore（持久化）
    └── 阿里云 KMS（签名密钥）

CoPaw Agent Runtime
    └── aip-identity-sdk（加载私钥、签名换 JWT、注入认证头）

CoPaw Hub / PawFriends, DojoZero
    └── aip-identity-verify（验签 JWT、识别 Agent 身份）
```

## 集成点

### 1. CLI：`copaw init`

用户首次使用时运行。内部调用 `aip-identity-sdk` 的管理 API。

```
copaw init
  → 调用 aip-idp 的 Device Flow（GitHub）或 Auth Code + PKCE（阿里云 ID）
  → 拿到 management_token
  → 保存到 ~/.copaw/config.json（或 ~/.aip/config.json）

copaw agent create --name shark
  → 本地生成 Ed25519 密钥对
  → 公钥注册到 aip-idp
  → 私钥保存到 ~/.aip/agents/shark/private_key
  → agent.json 保存 agent_id、kid、idp_url
```

CoPaw CLI 不需要自己实现密钥管理或 OAuth 流程——全部委托给 SDK。

### 2. Agent Runtime：透明认证

Agent 代码不感知 AIP。CoPaw 框架在启动时加载身份，自动注入认证头。

```python
# CoPaw 框架内部（agent 作者看不到这部分）
from aip_identity_sdk import AIPIdentity

identity = AIPIdentity.from_file("shark")  # 或 from_env()

# 每次请求 hub 时
token = get_or_refresh_jwt(identity, audience=hub_url)
headers["Authorization"] = f"AIP {token}"
```

```python
# Agent 作者的代码——不需要 import 任何 AIP 相关的东西
class SharkAgent(CoPawAgent):
    def act(self, observation):
        return self.hub.submit(my_prediction)  # 认证自动完成
```

### 3. Hub / OpenClaw Arena：验证 Agent 身份

Hub 使用 `aip-identity-verify` 验证传入请求。

```python
from aip_identity_verify import AIPVerifier

verifier = AIPVerifier(
    trusted_providers=["copaw.ai"],
    audience="https://arena.openclaw.ai",
)

# REST
agent = await verifier.verify(request.headers["Authorization"])

# WebSocket（OpenClaw 竞技场实时对战）
agent = await verifier.verify_token(ws_handshake_token)

# 根据身份决定权限
if agent.principal["type"] == "org":
    allow_premium_access()
```

## 数据流

```
首次注册（一次性）：
  开发者 → copaw init → aip-idp → GitHub/阿里云 OAuth → 主体创建
  开发者 → copaw agent create → 本地生成密钥 → aip-idp 注册公钥

运行时（每次请求）：
  Agent → aip-identity-sdk → 私钥签名 → aip-idp → JWT
  Agent → 带 JWT → OpenClaw Hub → aip-identity-verify → 验签通过 → 正常访问
```

## 身份存储

| 位置 | 内容 | 谁能访问 |
|------|------|----------|
| `~/.aip/config.json` | idp_url、principal_id、management_token | CLI |
| `~/.aip/agents/shark/agent.json` | agent_id、kid、idp_url | Agent runtime |
| `~/.aip/agents/shark/private_key` | Ed25519 私钥（权限 0600） | Agent runtime |
| aip-idp (TableStore) | 主体、Agent、公钥 | IdP 服务 |

私钥只存在于 Agent 运行的机器上。IdP 永远不持有私钥。

## 远程部署场景

Agent 跑在云服务器上，开发者在本地笔记本完成 OAuth：

```
笔记本（有浏览器）：
  copaw init → OAuth → management_token

云服务器（无浏览器）：
  copaw agent create --name shark --token <粘贴 management_token>
  → 密钥对在云服务器本地生成
  → Agent 就地运行
```

或通过环境变量（CI/CD）：

```bash
AIP_AGENT_ID=aip:copaw.ai:agent_xxx
AIP_AGENT_KID=abc123
AIP_PRIVATE_KEY=<hex>
AIP_IDP_URL=https://identity.copaw.ai
```

## CoPaw 需要做的事

| 任务 | 依赖 | 说明 |
|------|------|------|
| `copaw init` 命令 | aip-identity-sdk | 包装 SDK 的 OAuth + 注册流程 |
| Agent runtime 集成 | aip-identity-sdk | 框架启动时加载身份，请求时注入 header |
| Hub 验证中间件 | aip-identity-verify | FastAPI/WebSocket 中间件，验签 + 提取 agent 信息 |
| JWT 缓存 | 自行实现 | Agent runtime 缓存 JWT 直到接近过期，避免每次请求都换 token |

CoPaw 不需要自己实现任何密码学、OAuth 流程或 JWT 验签——全部由 AIP 栈提供。
