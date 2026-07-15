# AgentID Client SDK（Agent 侧）

`agent-id-client-sdk` 让 **agent** 从兼容协议的 IdP 获取短期 AgentID JWT，
并把它附加到访问 Agent身份互联应用（Agent Identity Connected App, IDA）的请求中。
下面的示例使用已上线的 ModelScope IdP 作为参考 IdP 实现；AgentID 不假设
ModelScope 是唯一 IdP。Agent 持有 Ed25519 私钥；IdP 持有此前注册的匹配公钥，
并在收到签名请求后签发 JWT。

这是 Agent 侧文档。IDA 侧通过
[`agent-id-service-sdk`](./agentid-service-sdk.zh.md) 验证这些 token。

---

## 安装

```bash
pip install agent-id-client-sdk
# 或在本 monorepo 中开发安装：
uv pip install -e agent-id-client-sdk
```

运行时依赖：`httpx`、`cryptography`、`pyjwt`。注册相关的 `providers/` 层也使用
`httpx`。

---

## 概念

| 对象 | 作用 |
| --- | --- |
| `Identity` | Agent 的凭证：`agent_id`、`kid`、Ed25519 私钥和 `idp_url`。负责签名 token 请求，不做管理面调用。 |
| `Client` | 异步 HTTP client，把 `Identity` 换成 token，并在请求中附加 `Authorization: Bearer <jwt>`；内置缓存和 401 后重试。 |
| `providers/` | **只用于 setup-time。** Provider 控制面，用于注册 agent、创建 IDA 应用。包含 `ModelScopeProvider`，它需要 ModelScope AccessToken。运行时路径不会 import 它。 |

两个阶段要分开：

1. **Provision（一次性 setup）：** 生成密钥对，把公钥注册到 IdP，拿到
   `agent_id`。ModelScope 示例需要 ModelScope AccessToken。
2. **Run（每次请求）：** 加载已保存的 `Identity`，签名，获取 JWT，调用 IDA。
   不需要 AccessToken，只需要 agent 私钥。

---

## 1. 创建身份（一次性）

Agent 身份通过把 Ed25519 公钥注册到 IdP 创建。使用已上线的 ModelScope IdP 时，
有两种方式：

### A. ModelScope 控制台

在 ModelScope 控制台进入 **Agent Identity → Identity management**，创建 agent。
控制台会展示一条 `openssl` 命令，用于在本地生成 `agent.pem`（Ed25519）和公钥
JWK。运行命令后，把 JWK 粘贴到控制台并提交。你会得到 `agent_id`（格式如
`agent_id:modelscope:agent_xxx`）和你选择的 `kid`。`agent.pem` 必须保密，
不要离开你的主机。

匹配的 **IDA**（token audience）需要单独在 **Agent Identity →
Identity Interconnection** → "Create Application" 下注册。注册后会得到
`client_id`，例如 `hub_xxxxxx`。域名验证是可选项。

### B. 通过 provider 层编程注册

适合脚本化 fleet provisioning。它需要 **ModelScope AccessToken**，这是高权限
管理凭证，不要放在 agent runtime 主机上。

```python
from agent_id_client_sdk.providers import provision_agent
from agent_id_client_sdk.providers.modelscope import ModelScopeProvider

provider = ModelScopeProvider(
    access_token="<modelscope-access-token>",
    base_url="https://www.modelscope.cn/openapi/v1",
)

# 生成 Ed25519 密钥对，注册公钥，并把 profile 保存到
# ~/.agentid/agents/my-agent/（agent.json + private_key）。
registered, private_key = provision_agent(provider, "my-agent")
print(registered.agent_id)  # agent_id:modelscope:agent_xxxx
```

只有公钥 JWK 会被上传，私钥保留在本地。`provision_agent` 会把 `idp_url`
（OpenAPI base）写入 profile，运行时 client 会用它获取 token。

> **已上线的 ModelScope IdP。** Public base URL 是
> `https://www.modelscope.cn/openapi/v1`。`POST /agent_id/token` 返回
> ModelScope response envelope，`POST /hub_apps` / `POST /agent_ids` 需要
> `Authorization: Bearer <ModelScope AccessToken>`。

---

## 2. 加载身份（每次运行）

```python
from agent_id_client_sdk import Identity

# 从已保存的 profile 目录加载（~/.agentid/agents/<name>/）：
identity = Identity.from_profile("my-agent")

# 或从环境变量加载：
#   AGENTID_AGENT_ID, AGENTID_AGENT_KID,
#   AGENTID_AGENT_PRIVATE_KEY（hex 32-byte seed）, AGENTID_IDP_URL
identity = Identity.from_env()

# 或从 zip bundle 加载（agent.json + private_key，内存读取）：
identity = Identity.from_zip("my-agent.zip")
```

> **ModelScope `idp_url` 必须显式配置。** `agent_id:modelscope:...` 本身不携带
> 可推导的 API host。profile / `AGENTID_IDP_URL` 必须包含真实 OpenAPI base，
> 例如 `https://www.modelscope.cn/openapi/v1`。`provision_agent` 会自动写入；
> 如果手动构造 `Identity(...)`，需要自己传入 `idp_url=`。

---

## 3. 获取 token 并调用 IDA

**audience** 是 IDA 在 ModelScope 注册得到的 **`client_id`**，例如
`hub_4abb08`，不是 origin URL。这个值由 IDA 运营方提供。

```python
from agent_id_client_sdk import Client

client = Client(identity, default_audience="hub_4abb08")  # dpop 默认关闭

# 原始 token（会缓存，并在过期前约 60 秒刷新）：
token = await client.get_token()

# 或让 client 自动附加 header：
resp = await client.post(
    "https://ida.example.com/api/agents/register",
    json={"agent_id": identity.agent_id},
)
resp.raise_for_status()
```

`Client` 按 audience 缓存 token，在过期前约 60 秒刷新；收到 `401` 时会清除缓存并
重试一次。

> **ModelScope 路径默认不启用 DPoP。** ModelScope token 不携带 `cnf.jkt`；
> 构造 `Client(identity, ...)` 时使用默认的 `dpop=False`。`dpop=True` 和
> `sign_dpop_proof` 仍保留给选择启用 DPoP 的自托管 IdP，例如设置
> `REF_AGENT_IDP_DPOP_ENABLED=1` 的 ref-idp。

---

## Token 流程（内部发生什么）

`Client.get_token(audience)`：

1. `timestamp = int(now)`（Unix epoch 秒；IdP 允许约 ±60 秒时钟偏移）。
2. 用 Ed25519 签名 `"{agent_id}|{kid}|{audience}|{timestamp}"`，输出
   **base64url，无 padding**（`Identity.sign_token_request`）。
3. `POST {idp_url}/agent_id/token`，请求体为
   `{agent_id, kid, audience, timestamp, signature}`。
4. 解开 ModelScope envelope：
   `{success, request_id, data:{access_token, token_type, expires_in, jti}}`。
   `expires_in` 是**相对秒数**，以请求时间为起点。

签发的 JWT 是最小 claims：`iss, sub (=agent_id), aud (=client_id), iat, exp,
jti`。不包含 `principal`、`scopes`、`delegation` 或 `cnf`。

---

## 配置速查

| 环境变量 | 使用方 | 含义 |
| --- | --- | --- |
| `AGENTID_AGENT_ID` | `Identity.from_env` | `agent_id:modelscope:agent_xxx` |
| `AGENTID_AGENT_KID` | `Identity.from_env` | 注册时选择的 key id |
| `AGENTID_AGENT_PRIVATE_KEY` | `Identity.from_env` | hex 编码的 32-byte Ed25519 seed |
| `AGENTID_IDP_URL` | `Identity.from_env` | OpenAPI base，例如 `https://www.modelscope.cn/openapi/v1` |
| `AGENTID_HOME` | profile store | Profile root，默认 `~/.agentid` |

---

## 参考应用：DojoZero

DojoZero 是参考应用接入示例，不是协议依赖。它的 client SDK（`dojozero-client`）
会透明封装 AgentID：`GatewayTransport` 接收 `agentid_client` 和
`agentid_audience`，并在每次 gateway 调用时附加 Bearer header。最终用户流程见
agent-side connect-to-Dojo skill。

`dojozero-agent` CLI 也直接暴露了 AgentID 配置（opt-in；GitHub PAT / API key
仍可用）：

```bash
dojozero-agent config --agentid-agent-id <agent_id> --agentid-kid <kid> \
  --agentid-key <agent.pem> --agentid-idp-url <idp_url> --agentid-audience <client_id>
```

之后 `dojozero-agent start <trial>` 会通过 AgentID 连接。

---

## 状态 / 缺口

- 已完成：运行时路径（签名 → `/agent_id/token` → 附加 Bearer）、base64url
  signature、int timestamp、envelope unwrap、按 audience 缓存和 401 后重试。
- 已完成：注册用 provider 层（`ModelScopeProvider`、`provision_agent`）。
- 已支持：已上线 ModelScope IdP 的 endpoint shape。
- 已验证：控制台注册流程，以及通过已上线 ModelScope IdP 跑通 token→verify。
- 已支持：DojoZero CLI 暴露（`dojozero-agent config --agentid-*`）。
- 已验证：SDK live provisioning（`provision_agent` / `create_hub_app`）可完成注册、
  round-trip 和清理；由默认跳过的 `test_modelscope_live.py` integration test 覆盖。
