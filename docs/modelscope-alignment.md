# 对齐 ModelScope Agent IdP — SDK 改造清单

魔搭（ModelScope）的 Agent IdP 已上线（test 环境 `https://test.modelscope.cn/openapi/v1`，
prod `https://www.modelscope.cn/openapi/v1`），且**已作为事实标准**。`agent-id-client-sdk`
（Agent 侧）与 `agent-id-service-sdk`（IDA/验签侧）需直接改为讲 ModelScope 协议——
**不做兼容层、不保留 shim**。

> 本清单已与两份材料交叉核对并一致：
> - ModelScope《agent id 接口文档》；
> - 团队 `modelscope_service/tests/agent_idp_demo` 的 shim 跑通记录
>   （demo-agent + demo-hub 端到端验证全绿）。
>
> 下面的改动 = 把那套 shim/monkey-patch 翻译点固化进 SDK：
> - `shim.py` 的字段/路径翻译 → 见 §一、§二；
> - `start_hub.py` 强制的 `trusted_providers/audience/provider_urls` → 普通 `Verifier(...)` 配置；
> - `run_agent.py` 的 `default_audience` + `dpop=False` → 普通 `Client(...)` 配置。

---

## 一、agent-id-client-sdk（Agent 侧）

### `identity.py`

| # | 位置 | 现状 | 改为 |
|---|------|------|------|
| 1 | `sign_token_request` (L171-178) | 返回 `signature.hex()` | 返回 `_b64u(signature)`（base64url，无 padding，复用 L246 helper） |
| 2 | `_idp_url_from_agent_id` (L39-58) | 从 agent_id 推导 IdP host，仅认 `agentid:` 前缀 | **放弃推导**：agent_id 为 `agent_id:modelscope:<id>`，不含可解析的 API host（更没有 `/openapi/v1/agent_id` 路径）。`idp_url` 改为必填显式配置（构造参数 / `AGENTID_IDP_URL` / `agent.json`）；该 helper 可删或仅留作 legacy fallback |
| 3 | `public_jwk` (L180-192) | 只含 `kty/crv/x` | 注册 JWK 需 `kid`（可含 `use:sig`/`alg:EdDSA`）：补 `"kid": self._kid` |

> 签名「消息体」格式不变，仍为 `{agent_id}|{kid}|{audience}|{timestamp}`，只改签名的**输出编码**（hex → base64url）。请求体里的 `agent_id` 必须与签名所用一致。

### `client.py`

| # | 位置 | 现状 | 改为 |
|---|------|------|------|
| 4 | `get_token` 请求 (L57-66) | `POST {idp}/agentid/token`；`"timestamp": str(timestamp)` | 路径 → `{idp}/agent_id/token`（注意单数 `agent_id`，token 端点在 `/openapi/v1/agent_id/` 下）；`timestamp` 改为 **int** |
| 5 | `get_token` 解析 (L68-71) | 读顶层 `data["token"]` / `data["expires_at"]`（绝对时间） | 解包 `{success, request_id, data}` 信封：`data["data"]["access_token"]`；`expires_in` 是**相对秒**，缓存算 `expires_at = now + expires_in`；`success=false` 时抛出并带上 `code`/`message` |
| 6 | `_audience_from_url` (L142-146) | audience = 资源 origin URL | audience = IDA 注册的 `client_id`（`hub_xxxxxx`），后端严格校验、拒绝任意 URL。必须显式 `default_audience="hub_xxxxxx"`，不再用 origin 推导 |
| 7 | DPoP (`_attach_auth_headers`) | 支持 DPoP | ModelScope 暂不签 `cnf.jkt`，**已确认不做 DPoP**。固定 `dpop=False` |

---

## 二、agent-id-service-sdk（IDA / 验签侧）

### `verifier.py`

| # | 位置 | 现状 | 改为 |
|---|------|------|------|
| 8 | `_fetch_jwks` 发现 (L215-244) | `GET {https://domain}/.well-known/agentid-configuration`，再对 `jwks_uri` 路径重写 | discovery 与 jwks 实际在 `/openapi/v1/agent_id/` 下。两条路：① **首选**：后端把 OIDC 文档里的 `iss`/`token_endpoint`/`jwks_uri` 改成正确且一致的**绝对 URL**，SDK 直接用广播的 `jwks_uri`，去掉 L238-240 易翻倍的路径重写；② SDK 加 `jwks_urls: dict[domain,url]` 显式覆盖，命中即跳过发现 |
| 9 | 构造参数 `audience` | 传 origin URL | 改传 IDA `client_id`（调用方配置，SDK 无需改） |
| 10 | trusted / issuer | — | issuer 按 **domain** 比对：`trusted_providers=["test.modelscope.cn"]`（prod 用 `www.modelscope.cn`/`modelscope.cn`），按环境配置 |
| 11 | `VerifiedAgent` (L518-531) | 期望 `principal/capabilities/scopes/delegation/agent_token_version` | ModelScope JWT 仅 `iss/sub/aud/iat/exp/jti`，上述字段全走空默认值。**无需改代码**，但：不要启用 `min_agent_token_version`（恒 0）；`dpop_mode` 不可设 `required`；发现文档无 `activity_endpoint`，活动上报需显式传入否则停用；依赖 `agent_id`(=`sub`) 的逻辑按其原值处理（`agent_id:modelscope:...`，勿假设 `aip:` 前缀） |

> `algorithms` 已含 `EdDSA`，`require:[exp,iss,aud]` 均满足，JWKS 解析已支持 OKP/Ed25519，无需改动。

覆盖示例：
```python
Verifier(
    trusted_providers=["test.modelscope.cn"],   # 按环境
    audience="hub_4abb08",                        # 已注册 client_id
    jwks_urls={"test.modelscope.cn":
        "https://test.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks"},
    dpop_mode="optional",                         # 不可 required
)
```

---

## 三、协议事实（原「待确认」已确认）

| 项 | 结论 |
|---|------|
| `sub` 格式 | = 注册返回的 agent_id `agent_id:modelscope:agent_xxx`（线上 pre 实测如此，定为规范格式；早期文档写的 `aip:identity.modelscope.cn:...` 为旧式假设。SDK 按原值签名，故运行时两种都能用，但规范/线上签发用 `agent_id:modelscope:`） |
| `aud` | = 已注册 `hub_app.client_id`（如 `hub_4abb08`），后端 `IssueToken` 强校验，拒绝任意 URL |
| issuer / JWKS host | issuer 真实为上游域名（test `test.modelscope.cn`），IDA 按 **domain** 配 `trusted_providers`；JWKS 经 `provider_urls`/`jwks_urls` 指向 `/openapi/v1/agent_id/.well-known/agentid-jwks` |
| 路径单复数 | CRUD 用复数 `agent_ids`/`hub_apps`；token 与 well-known 用单数 `agent_id/...` |

---

## 四、其他需注意（接口文档约束）

- **timestamp 有效窗口 ±60s**（接口文档 §2.1）：比 ref-idp 的 5min 紧很多，时钟偏移 >60s → `InputParameterError`。需保证 NTP 同步。
- **`token_expire_time` ≤ 3600s（1h）**：可选 300/600/1800/3600，注册时设定，无法签发更长 token。
- **单活跃密钥**：轮换走 `PUT /agent_ids/:agent_id/key_pairs`，旧钥立即失效；无多钥并存。
- **错误响应** `{success:false, code, message}`：client 应解析并上抛 `code`/`message`。
- **注册/IDA 应用（HubApp API）鉴权**：`Authorization: Bearer <ModelScope AccessToken>`（`MS_TOKEN`），走上游 OpenAPI 网关，不经 SDK token 流程。

---

## 五、落地策略

1. 把 §一/§二的改动直接固化进 SDK（替代 shim 的字段/路径翻译）。
2. `start_hub.py` / `run_agent.py` 的强制项降级为普通 SDK 配置（见上方覆盖示例）。
3. 后端（我方自有）清理 OIDC 发现文档，广播正确一致的绝对 URL，免去验签侧 rewrite hack。
4. 跨厂商互认相关的低优项（`aip:` vs `agentid:` 前缀、`approval_endpoint`、DPoP `cnf.jkt`）按需二期再议——当前**确认不做**。

---

## 六、DojoZero 对齐范围

> 决策（2026-06-24）：**活动上报（aip-activity）与审批（approvals）均二期再做**。Day-one 只做必需层。

DojoZero 同时消费两个 SDK：网关（IDA，service SDK）+ agent-runner/客户端（client SDK）。
关键前提：网关实际只用到 JWT 的 `sub`（→ `agent_id`）；`principal/agent_name/scopes/
capabilities/delegation/token_version/cnf` 要么硬编码为空、要么从不读取
（见 `gateway/_activity.py:_build_verified_agent`），故 ModelScope 的精简 JWT **优雅降级**而非报错。

### Day-one 范围

| 层 | 代码改动 | 配置 / 引导 |
|---|---|---|
| **SDK**（基础） | §一 / §二 | — |
| **网关 / IDA**（`agent_id_service_sdk`） | `gateway/_agentid.py`：把 SDK 新增的 JWKS 解析参数（`jwks_urls`）透传进 `Verifier(...)`。`audience` 本就是透传 env 值、Verifier 不校验 URL 格式，无需改校验逻辑 | `DOJOZERO_AGENTID_TRUSTED_PROVIDERS=test.modelscope.cn`（prod 用 `www.modelscope.cn`）；`DOJOZERO_AGENTID_AUDIENCE=<我方 IDA client_id>`（**语义变更**：原为网关 origin URL）；JWKS 覆盖指向 `/openapi/v1/agent_id/.well-known/agentid-jwks` |
| **agent-runner / 客户端**（`agent_id_client_sdk`） | `agent-runner/_config.py:99-107` 与 `_runner.py:38` 默认把 audience 退回 `gateway_url`/dashboard origin——对 ModelScope 错误。加 guard：启用 AgentID 时**强制** `DOJOZERO_AGENTID_AUDIENCE`(=client_id)，不再回退 URL。可选加 `AGENTID_IDP_URL` 透传 | `idp_url` 现仅来自 profile `agent.json`（`_runner.py:37`）——须保证 ModelScope 注册产出的 profile 内含 `idp_url`（`register_agent.py` 已写入）。token 附带为 Bearer-only、解析全交给 SDK（`_transport.py:140-149`），无需改 |
| **ModelScope 注册引导**（ops，非代码） | — | ① 用 ModelScope AccessToken 把网关注册为 **IDA 应用**（API 对象仍是 `hub_app`）→ 取得两端共用的 `client_id`；② 逐个注册 **agent** → 生成内含 `idp_url` + `audience=client_id` 的 profile |

### 二期 / 暂不做

| 项 | 处置 |
|---|------|
| **活动上报**（aip-activity, Layer 3） | 二期。届时 aip-activity 的 verifier 也需配 ModelScope issuer/JWKS（同 §二，配置为主）；ModelScope JWT 无 principal，事件 `principal_id` 为空、按 `agent_id` 过滤（与现设计一致） |
| **审批**（IdP 代理审批） | 关闭。`request_approval=False`，`ApprovalCoordinator` 保持 `None`（`_server.py:258-310` 已干净 no-op）。DojoZero 的 `_approvals.py` 是 **IdP 代理式**（POST `/agentid/approvals` + 验 decision JWT，`_approvals.py:361-422,644-670`），ModelScope 无此端点。等 ModelScope 上线审批端点或改做网关本地审批再启 |
| **DPoP / token-versions / IDA trust-list / manifest discovery** | ModelScope 路径不涉及；IDA publisher / HubJWS 签名钥仍属我方，仅活动上报开启时才用 |

### 落地顺序

1. SDK 改动（§一/§二，基础）
2. 网关 `_agentid.py` 透传 `jwks_urls` + 配置值
3. agent-runner audience guard（+ 可选 `AGENTID_IDP_URL`）
4. ModelScope 注册引导（hub_app + agents）——打通端到端的前置
5. （二期）aip-activity 配置；（二期）审批
