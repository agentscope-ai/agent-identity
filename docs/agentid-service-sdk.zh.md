# AgentID Service SDK（Hub 侧，ModelScope 版）

`agent-id-service-sdk` 让 **Hub**（资源服务器，例如 API gateway）验证
Agent 请求中携带的 AgentID JWT。它会用 IdP 发布的公钥检查签名，并校验 issuer、
audience、过期时间，最后返回调用方身份。

这是 Hub 侧文档。Agent 侧通过
[`agent-id-client-sdk`](./agentid-client-sdk.md) 获取 token。

> 本文对应 ModelScope 对齐后的 SDK。底层协议改动清单见
> [`modelscope-alignment.md`](./modelscope-alignment.md)。

---

## 安装

```bash
pip install agent-id-service-sdk
# 可选 setup-time helper：只有用 Python 注册 hub app 时才需要：
pip install agent-id-client-sdk
# 或者在本 monorepo 中开发安装：
uv pip install -e agent-id-service-sdk
uv pip install -e agent-id-client-sdk
```

运行时依赖：`httpx`、`cryptography`、`pyjwt[crypto]`、`tldextract`。

`agent-id-service-sdk` 是运行时验签依赖。Hub serving runtime **不需要**
`agent-id-client-sdk`。它只出现在下文，是因为 Python setup helper
`ModelScopeProvider.create_hub_app(...)` 目前放在
`agent_id_client_sdk.providers.modelscope` 里。如果你通过 ModelScope 控制台注册
hub app，或直接调用 `POST /hub_apps`，可以跳过 `agent-id-client-sdk`。

---

## 前置条件：注册 Hub，拿到 `client_id`

在 ModelScope 路径下，ModelScope 是 Hub 身份的中心登记方。仅做 token
认证时，Hub 不需要先自发布 `.well-known` manifest 或 JWKS。你需要先把 Hub
注册成一个 ModelScope hub app，ModelScope 会返回 `client_id`。这个
`client_id` 就是所有 Agent 获取 token 时必须填写的 **`aud`**，也是 Hub
验签时必须强制匹配的 `audience`。

### A. ModelScope 控制台

在 ModelScope 控制台进入 **Agent Identity → Identity Interconnection**，
选择 **Create Application**。填写 Hub 应用名称和 homepage / service endpoint
后提交，并保存返回的 `client_id`（例如 `hub_4abb08`）。这个 `client_id`
就是 agents 获取 token 时填写的 audience，也是 Hub 构造
`Verifier(audience=...)` 时必须使用的值。

控制台可能还会提供域名 **Verify** 操作。这个操作对 token 认证不是必需项；
见下面的说明。

### B. Python helper 或直接调用 OpenAPI

适合脚本化注册 Hub。它需要 ModelScope AccessToken，效果等价于直接调用
`POST /hub_apps`。

```python
from agent_id_client_sdk.providers.modelscope import ModelScopeProvider

provider = ModelScopeProvider(
    "<modelscope-access-token>",
    base_url="https://www.modelscope.cn/openapi/v1",
)
hub = provider.create_hub_app(
    app_name="MyHub",
    app_homepage="https://hub.example.com",
)
print(hub.client_id)  # 例如 hub_4abb08，这就是 verifier 的 audience
```

> ModelScope 可选的 `POST /hub_apps/endpoints/validate` 会探测
> `/.well-known/manifest`。如果你的 Hub 只做被动 token 验签，这个探测不会通过。
> 直接调用 `POST /hub_apps` 注册即可；`client_id` 的签发不依赖这个预检。

> **域名验证（控制台里的 Verify / `endpoints/validate`）不是 token
> 认证的前置条件。** 它探测的 `/.well-known/manifest` 主要用于两件事：
> 一是 verified-hub 信任标识，证明你拥有 Service Endpoint 域名；二是后续活动上报，
> 让 Hub 发布自己的签名公钥。它不参与 Agent token 的签发或验签。如果你的 Hub
> 只是被动验签（不发布 manifest），只有要做 verified-hub 标识或活动上报时，
> 才需要补上 manifest/JWKS。

> 预发环境已验证（2026-06-26）：`POST /hub_apps` 在没有 token 时返回
> ModelScope envelope（`InvalidAuthentication`）；注册时需要传
> `Authorization: Bearer <ModelScope AccessToken>`。

### 已验证的预发端点（2026-06-26）

来自：

```text
GET https://pre.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-configuration
```

| 字段 | 值 |
| --- | --- |
| `issuer` | `https://pre.modelscope.cn/openapi/v1`。验签配置中按 host 写入 `trusted_providers`，即 `pre.modelscope.cn` |
| `jwks_uri` | `https://pre.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks`，用于 `jwks_urls` |
| `token_endpoint` | `https://pre.modelscope.cn/openapi/v1/agent_id/token` |
| signing alg | `EdDSA`。预发发现文档中它是 JSON 字符串，不是数组；因为我们直接 pin `jwks_urls` 并跳过 discovery，所以这不影响验签 |
| JWKS kids | `idp-key-001`、`idp-key-002`，均为 `OKP` / `Ed25519` / `use=sig` |

---

## 新 Hub 上线检查清单

一个全新的 Hub 要开始服务 ModelScope AgentID agents，最小路径是：

1. 在 ModelScope 控制台注册 Hub（**Agent Identity → Identity Interconnection
   → Create Application**），或通过 `create_hub_app(...)` / 直接
   `POST /hub_apps` 注册；保存返回的 `client_id`。
2. 用同一套 ModelScope 环境配置一个 `Verifier`：`trusted_providers`、
   `audience=<client_id>`、`jwks_urls`、`dpop_mode="disabled"`。
3. 把 verifier 接入所有受保护路由。没有 `Authorization: Bearer <jwt>` 的请求直接拒绝；
   业务授权只使用 `verified.agent_id`。
4. 确认调用方 agents 已经拥有 ModelScope AgentID 身份。Agent 注册与配置见
   [`agentid-client-sdk.md`](./agentid-client-sdk.md)。
5. 给 agent operator 明确四项信息：Hub API base URL、Hub `client_id` audience、
   ModelScope IdP base URL、以及认证格式 `Authorization: Bearer <jwt>`。
6. 环境必须一致。预发环境统一使用 `pre.modelscope.cn` 和
   `https://pre.modelscope.cn/openapi/v1`；生产环境统一使用 `www.modelscope.cn`
   和 `https://www.modelscope.cn/openapi/v1`。混用预发/生产配置会导致 issuer、
   JWKS 或 audience 校验失败。

如果通过 Python helper 或 OpenAPI 注册，使用的 ModelScope AccessToken 是
setup-time 管理凭证。不要放进 agent runtime 配置，也不要要求 agents 把它发给你的 Hub。

---

## 验证 token

```python
from agent_id_service_sdk import Verifier

verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],  # 信任的 issuer host
    audience="hub_4abb08",                    # 注册 Hub 后拿到的 client_id
    # Verifier 默认会访问 https://{domain}/.well-known/agentid-configuration。
    # 但 ModelScope 的发现与 JWKS 在 /openapi/v1/agent_id/... 下，域名根路径
    # 返回 web app HTML。因此生产集成应直接 pin JWKS URL：
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    # ModelScope token 不带 cnf.jkt；这条路径不要启用 DPoP。
    # SDK v0.6 默认是 optional，因此这里要显式 disabled。
    dpop_mode="disabled",
)

verified = await verifier.verify(authorization_header)  # "Bearer <jwt>"
print(verified.agent_id)    # sub，例如 agent_id:modelscope:agent_xxx
print(verified.issuer)      # iss
print(verified.expires_at)  # exp，datetime
```

`verify` 失败时会抛异常，例如：

| 异常 | 含义 |
| --- | --- |
| `ProviderUntrustedError` | JWT `iss` 的 host 不在 `trusted_providers` 中 |
| `TokenExpiredError` | token 已过期 |
| `SignatureInvalidError` | JWT 签名校验失败 |
| `TokenInvalidError` | audience 错误、JWT 格式错误、缺少必要字段等 |

### 具体校验项

1. **Issuer**：JWT `iss` 的 host 必须在 `trusted_providers` 中，按 domain 匹配。
2. **Signature**：用 IdP JWKS 验签；ModelScope 路径建议从 `jwks_urls` 拉取并按 `cache_ttl` 缓存。
3. **Audience**：JWT `aud` 必须等于 `audience`，也就是注册 Hub 后得到的 `client_id`。
4. **Expiry**：`exp` 必须有效，允许 `clock_skew_seconds` 的时钟误差。

### ModelScope token 是最小 claims

ModelScope JWT 当前只保证最小 claims。返回的 `VerifiedAgent` 中，以下字段可用：

- `agent_id`
- `issuer`
- `expires_at`
- `raw_jwt`
- `raw_claims`

更丰富的字段，例如 `principal`、`capabilities`、`scopes`、`delegation`、
`model_info`、`agent_token_version`，在 ModelScope 路径下会是空值或默认值。
Hub 的授权逻辑应基于 `agent_id`，不要依赖 principal/scopes。

---

## 最小 FastAPI 接入示例

Verifier 本身不绑定具体传输协议；在 HTTP 服务中，建议保留一个 verifier 实例，
再通过 auth dependency 复用它：

```python
from fastapi import Depends, FastAPI, Header, HTTPException
from agent_id_service_sdk import AgentIDError, Verifier

app = FastAPI()

verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],
    audience="hub_4abb08",
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    dpop_mode="disabled",
)


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
    # 业务授权基于 agent.agent_id；不要相信请求体里自报的 agent_id。
    return {"accepted_for": agent.agent_id}
```

如果你的服务不是 FastAPI，规则也一样：取完整 `Authorization` header，调用
`await verifier.verify(header)`，失败时返回 401，并且只把返回的 `VerifiedAgent`
当作调用方身份。

---

## 构造参数速查

| 参数 | ModelScope 推荐值 |
| --- | --- |
| `trusted_providers` | 生产：`["www.modelscope.cn"]`；预发：`["pre.modelscope.cn"]` |
| `audience` | 注册 Hub 后拿到的 `client_id`，例如 `"hub_4abb08"` |
| `jwks_urls` | `{domain: ".../agent_id/.well-known/agentid-jwks"}`。直接指定 JWKS，跳过 discovery |
| `dpop_mode` | `"disabled"`。不要依赖 SDK 默认值 |
| `cache_ttl` | JWKS 缓存秒数，默认 3600 |
| `clock_skew_seconds` | `exp` / `iat` 容忍秒数，默认 30 |
| `provider_urls` | discovery base override，主要用于本地开发 |

活动上报相关参数（`activity_endpoint`、`hub_signing_key` 等）不参与
ModelScope IdP token 验证。活动上报是单独能力；后续如果要做活动上报，
需要单独配置 activity endpoint 与 Hub 签名密钥。

---

## 状态 / 缺口

- 已完成：issuer、audience、exp、signature 验证。
- 已完成：`jwks_urls` 直接指定 JWKS，绕过 ModelScope discovery 路径差异。
- 已完成：ModelScope 路径显式 `dpop_mode="disabled"`，处理最小 claims。
- 已验证过：预发 discovery + JWKS 可达；Hub `client_id` 签发与真实 token 验签已跑通。
- 暂缓：活动上报与审批。ModelScope IdP 当前不暴露这两类能力。
