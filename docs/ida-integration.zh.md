# IDA 接入指南

本文说明如何让一个服务接受通过 AgentID 认证的请求。这个服务的角色是
**Agent身份互联应用（Agent Identity Connected App, IDA）**：它接收 agent
发送的 `Authorization: Bearer <jwt>`，根据可信 IdP 的公钥验证 JWT，并基于
已验证的 agent 身份执行业务授权。

英文版：[ida-integration.md](./ida-integration.md)

IDA 侧 SDK API 见 [agentid-service-sdk.zh.md](./agentid-service-sdk.zh.md)。
Agent 侧流程见 [agentid-client-sdk.zh.md](./agentid-client-sdk.zh.md)。

本文配置示例使用已上线的 ModelScope IdP 作为参考 IdP 实现。AgentID 不假设
ModelScope 是唯一 IdP；请根据你选择信任的 IdP issuer 配置 verifier。

## 你需要实现什么

一个 IDA 接入需要承担四个运行时职责：

1. 决定信任哪些 IdP issuer。
2. 配置你的 IDA 期望的 JWT audience。
3. 在执行业务逻辑前验证每一个受保护请求。
4. 基于已验证的 `agent_id` 授权，不信任请求体里自报的身份字段。

使用已上线的 ModelScope IdP 时，audience 是 IDA 应用注册得到的 `client_id`，
例如 `hub_4abb08`。其他 IdP 实现可以采用不同的 audience 约定；verifier 配置
必须与签发 token 的 IdP 保持一致。

活动上报和审批工作流不在本文范围内。Layer 0 身份认证和 token 验签不依赖它们。

## 前置条件

- Python 3.10+。
- 已安装 `agent-id-service-sdk`。
- 一个 IDA audience。使用 ModelScope 时，在 **Agent Identity → Identity
  Interconnection → Create Application** 注册 IDA，并保存返回的 `client_id`。
- 每个可信 IdP 的配置：issuer host 和 JWKS URL。

```bash
pip install agent-id-service-sdk
```

## 配置 Verifier

在应用启动时创建一个 `Verifier`，并在所有受保护路由中复用。下面示例接受来自
已上线 ModelScope IdP 的 token：

```python
from agent_id_service_sdk import Verifier

verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],
    audience="hub_4abb08",  # IDA 应用注册得到的 client_id
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    dpop_mode="disabled",
)
```

配置说明：

- `trusted_providers` 是你的 IDA 接受的 issuer host 列表。
- `audience` 必须与传入 JWT 的 `aud` claim 一致。
- `jwks_urls` 指定 issuer 的公钥端点。
- `dpop_mode="disabled"` 适用于当前 ModelScope JWT 路径，因为这些 token
  不携带 `cnf.jkt`。

## 保护 HTTP 路由

在 HTTP 服务中，把完整的 `Authorization` header 传给 `verify()`：

```python
from fastapi import Depends, FastAPI, Header, HTTPException
from agent_id_service_sdk import AgentIDError

app = FastAPI()


async def get_agent(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(401, "Authorization: Bearer <jwt> required")
    try:
        return await verifier.verify(authorization)
    except AgentIDError:
        raise HTTPException(401, "AgentID token verification failed")


@app.get("/agents/whoami")
async def whoami(agent=Depends(get_agent)):
    return {
        "agent_id": agent.agent_id,
        "issuer": agent.issuer,
        "expires_at": agent.expires_at.isoformat() if agent.expires_at else None,
    }


@app.post("/work")
async def do_work(payload: dict, agent=Depends(get_agent)):
    # 业务授权基于已验证身份，不信任 payload["agent_id"]。
    return {"accepted_for": agent.agent_id}
```

对于 WebSocket、gRPC、MCP 或其他传输协议，提取原始 JWT 后调用
`verify_token(raw_jwt)`。

## Verifier 会检查什么

`Verifier` 会拒绝未通过以下检查的 token：

- `iss` host 必须在 `trusted_providers` 中。
- JWT 签名必须能用 issuer 的 JWKS 验证。
- `aud` claim 必须等于配置的 `audience`。
- token 必须在有效时间窗口内。

当前 ModelScope JWT 路径只保证最小 claims。建议围绕 `agent.agent_id`、
`agent.issuer` 和你自己的应用策略做授权。除非你信任的 issuer 明确文档化并签发
`principal`、`scopes` 或 `delegation`，否则不要假设它们存在。

## 给 Agent 的接入信息

Agent operator 需要以下信息才能调用你的 IDA：

- 你的 API base URL。
- 你的 IDA audience。使用 ModelScope 时，这是注册得到的 `client_id`。
- Agent 应该向哪个 IdP base URL 请求 token。
- 请求格式：`Authorization: Bearer <jwt>`。

Agent 侧示例：

```python
from agent_id_client_sdk import Client, Identity

identity = Identity.from_profile("my-agent")
client = Client(identity, default_audience="hub_4abb08")

response = await client.post("https://ida.example.com/work", json={"task": "run"})
response.raise_for_status()
```

## 上线检查清单

- IdP issuer host、JWKS URL 和 audience 必须来自同一套环境。
- 不要要求 agents 把 ModelScope AccessToken 发给你的 IDA。AccessToken 只应作为
  setup-time 管理凭证使用。
- 复用同一个 verifier 实例，让 JWKS 缓存生效。
- 认证失败返回 `401`；已认证但没有业务权限返回 `403`。
- 记录验签失败时不要记录完整 JWT。
- 为缺少 token、不可信 issuer、错误 audience、过期 token 和验签成功添加测试。
