# 审批场景

AgentID 协议规范（§7.6 授权许可与审批工作流）的配套文档。**非规范性**——本文档不定义任何强制要求。它的作用是把两种审批模式落在一个真实部署里，让读者理解协议_为什么_长成这样。

本文收录一个场景——**Acme 公司的 Rita**——作为 IdP 委托审批（规范 §7.6.7）的标准范例。未来可能加入更多场景。

---

## 1. 背景设定

**Rita** 是 **Acme 公司**的一位资深工程师。Acme 在 `idp.acme.com` 运营自己的 AgentID 身份提供方，由 Acme 身份团队负责，接入了公司的 SSO。每位 Acme 员工在上面都已经有账号。

公司里三个内部平台团队各自运营一个 AgentID 服务方：

| 服务方 | 团队 | 守护的资源 |
|---|---|---|
| `deploy-hub.acme.com` | DevOps | Kubernetes 部署、回滚、扩缩容 |
| `data-hub.acme.com` | 数据平台 | BigQuery / Snowflake / S3 访问 |
| `obs-hub.acme.com` | SRE | Grafana 面板、日志导出、生产环境 SSH |

三个服务方都信任 IdP 的签名密钥（通过 JWKS），但对 Rita 本人并不了解——它们只知道她拥有哪些智能体。

Rita 在 IdP 上以她作为主体注册了三个智能体：

- `deploy-bot` —— 负责 CI/CD 部署
- `analytics-bot` —— 负责临时分析查询
- `incident-bot` —— on-call 期间拉日志和监控指标

## 2. 自主路径

周一早晨。Rita 的智能体安静地干活：

- `deploy-bot` 把 `checkout-service` 部署到**预发环境**——在 `deploy-hub` 允许的自主策略范围内。
- `analytics-bot` 跑 `SELECT COUNT(*) FROM orders WHERE region='us-west'`——`data-hub` 允许非 PII 的只读查询。
- `incident-bot` 拉 `prod-us-east` 的 CPU 图表——`obs-hub` 对仪表盘完全放行。

没有任何审批流程触发。每个服务方用各自的策略评估令牌中的声明，自主决定。这是 AgentID 的基线路径——第 1 层声明 + 服务方本地执行，没有人工参与。

## 3. 审批路径（§7.6.7 Model 3）

**上午 10:52。** Rita 的发布流水线需要把 `checkout-service v2.14` 推到 **prod-us-west**。

`deploy-bot` 发起请求。`deploy-hub` 检查智能体的委托声明：`{environments: [staging, prod-eu]}`。`prod-us-west` 不在列表里。服务方策略规定："智能体委托范围外的生产部署需要主体审批。"

服务方此前已经拉过 `idp.acme.com/.well-known/aip-configuration`，发现声明了 `approval_endpoint`。它提交请求：

```http
POST https://idp.acme.com/aip/approvals
Content-Type: application/json

{
  "hub_id": "https://deploy-hub.acme.com",
  "agent_id": "aip:acme.com:agent_deploy_bot_rita",
  "resource": "/api/deploy",
  "action": "deploy.execute",
  "details": {
    "env": "prod-us-west",
    "service": "checkout-service",
    "version": "v2.14"
  },
  "reason": "部署环境 prod-us-west 超出委托范围"
}
```

IdP 创建一条待处理审批，绑定到 Rita 的主体。返回 `approval_id=apr_abc123`。`deploy-hub` 向 `deploy-bot` 返回 `202`，后者开始轮询。

**上午 10:52:03。** Rita 手机震动。Acme IdP 应用的推送通知：

> **deploy-bot** 想把 **checkout-service v2.14** 部署到 **prod-us-west**。批准？

她点开。应用里她已经登录着，显示审批卡片和请求详情。Face ID 确认。她点 **批准**。

幕后发生的：

1. 手机调用 `POST idp.acme.com/aip/portal/approvals/apr_abc123/approve`，携带 Rita 的管理令牌。
2. IdP 用_和签发智能体令牌同一把密钥_签出一份决策 JWT：
   ```json
   {
     "iss": "https://idp.acme.com",
     "sub": "aip:acme.com:agent_deploy_bot_rita",
     "aud": "https://deploy-hub.acme.com",
     "type": "approval_decision",
     "approval_id": "apr_abc123",
     "decision": "approved",
     "constraints": {
       "env": "prod-us-west",
       "service": "checkout-service",
       "version": "v2.14"
     },
     "approved_by": "rita@acme.com",
     "exp": 1713801800
   }
   ```
3. IdP 把 JWT 写进该审批记录。

**上午 10:52:07。** `deploy-bot` 一直每 2 秒轮询 `deploy-hub`。这次轮询时 `deploy-hub` 顺手向 IdP 轮询一次，拿到 `{status: "approved", decision_jwt: "..."}`。用 JWKS 验证 JWT 签名（已经缓存过——验证智能体令牌时拉的，无需新的网络请求）。检查 `aud == deploy-hub`、`sub == agent_id`。按 JWT 中的 constraints 签发本地许可。

**上午 10:52:09。** `deploy-bot` 再次轮询。`deploy-hub` 返回许可。`deploy-bot` 带 `X-AIP-Grant: gnt_...` 重试部署。`deploy-hub` 消耗许可（单次使用），执行部署。

**上午 10:53。** Rita 手机弹出后续通知："部署完成。" 她划掉，继续喝咖啡。

与此同时，如果 `analytics-bot` 也触发了审批阈值——比如查询客户 PII 表——同样的流程会在 `data-hub` 与同一个 IdP 之间重复一遍。**Rita 看到的是一个跨三个服务方的统一审批队列，每次请求只需决策一次，无论哪个服务方发起。**

## 4. Rita 为什么用 IdP（而不是别的）

这是本场景想回答的核心问题。Rita 本可以在许多地方完成审批，为什么是 IdP？Acme 的身份团队把每一种替代方案都评估过，最终都被否决了。

### 每个服务方各建一个审批门户

DevOps 做一个审批 UI。数据团队做另一个。SRE 做另一个。Rita 有三个收件箱、三种登录流、三套界面。她经理配置 PTO 期间的代审批要在三个地方各配一次。等 Acme 规模扩大（更多团队接入 AgentID，服务方数量上到几十个），方案在自身复杂度下崩溃。

### Slack 机器人审批

实现快。但：用表情包批准无法留下密码学审计记录。消息会被其他消息淹没。移动端体验是 Slack 的，不是 Acme 的。合规团队无法验证"发表情的人就是真正的主体"。Q4 审计时没有一条查询能一次性拉出所需数据。

### 邮件 magic link

链接会过期。收件箱变成噪音。没有移动推送。没有代审批支持。否决。

### 云原生审批（AWS IAM Identity Center、Azure PIM、阿里云 Access Manager）

每个在_自家云里_都挺好用。但 `deploy-bot` 往 GCP 部署、`analytics-bot` 查 Snowflake、`incident-bot` 用 Datadog。三套厂商 UI、三份审计孤岛、没有跨云视图。Acme 若把某个服务迁到别的云，审批体验也跟着变。对多云组织无法接受。

### 专门的审批 SaaS

多一个供应商、多一个信任根、多一份合同。每个服务方都要多做一次集成。IdP 能做的事情就没必要再引入一个。

### IdP 独有的能力

1. **Rita 已经在那里认证过。** SSO、MFA、会话都在。审批到来时不需要再登一次。
2. **它本来就在给这些服务方签东西。** 服务方验证的每一个智能体令牌都由这个 IdP 签发。签名决策复用同一个信任根和密钥基础设施——无新密钥、无新信任建立。
3. **它是唯一知道"主体↔智能体"关系的地方。** 服务方看到的是 agent_id；IdP 知道这个智能体属于谁、委托范围是什么、代审批人是谁。
4. **它是 Acme 自己的基础设施。** 合规、审计留存、数据驻留都遵循公司现有政策。
5. **N 个服务方共享一个收件箱。** Acme 随着时间增加服务方时能平滑扩张。
6. **治理自然贴合。** "Q4 所有特权操作、谁批的、什么时候批的"是一条查询、一个数据库、每行都带密码学证据。
7. **移动推送、代审批（PTO 覆盖）都在这里。** 配置一次，自动适用到所有服务方。

## 5. 场景守住的架构边界

IdP 委托审批不会破坏 AgentID 联邦叙事，原因在于它严守的职责切分：

- **服务方决定策略。** 只有 `deploy-hub` 知道 `prod-us-west` 超出了委托范围；只有 `data-hub` 知道哪些表是 PII。服务方决定_什么时候_需要审批，以及许可上附加_什么约束_。
- **IdP 决定"让谁决策"。** 它知道主体是谁、设备是哪台、代审批人是谁。它路由决策、签发决策。它_不_评估策略本身。

如果这条边界模糊了——IdP 开始评估时段规则、IP 白名单、资源标签——那么每朵云上的每个服务方都要开始说同一种策略语言，联邦就崩了。规范 §7.6.7.5 把这条写为明确的设计不变式。

## 6. 核心结论

- **Model 1（服务方本地）是基线。** 当组织没有统一身份基座，或者审批人在 IdP 触达范围之外时用它。
- **Model 3（IdP 委托）在组织已经运营自己 IdP、且多个服务方服务于同一主体群时回报最大。** Rita 的故事就是典型案例。
- **边界很重要。** 服务方守住自己知道的（策略、执行）；IdP 守住自己知道的（人、签名）。不要让边界漂移。
- **智能体不用改。** 两种模式下它们看到的都是同一套 `202 + 轮询 + 带许可重试`。委托对它们完全透明——所以服务方可以根据 IdP 发现文档自动切换模式，智能体侧不需要任何配合。
