# agent-id-service-sdk

AgentID Service SDK 用于 Agent身份互联应用（Agent Identity Connected App,
IDA）和 API 服务验证可信、兼容协议的 IdP 签发的 AgentID JWT。下面的示例使用
已上线的 ModelScope IdP。

英文版：[README.md](README.md)

## 安装

```bash
pip install agent-id-service-sdk
```

## 快速开始

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

# HTTP (REST)
agent = await verifier.verify(request.headers["Authorization"])  # "Bearer <jwt>"

# WebSocket / gRPC / MCP：用 verify_token() 传入原始 JWT
agent = await verifier.verify_token(raw_jwt_string)

print(f"Agent: {agent.agent_id}, Issuer: {agent.issuer}")
```

## 功能

- **传输协议无关**：HTTP header 用 `verify()`，WebSocket、gRPC、MCP 等原始 JWT 场景用 `verify_token()`
- **兼容协议的 IdP 验签**：验证来自可信 issuer 的 AgentID JWT，包括已上线的 ModelScope IdP
- **密钥轮换容错**：遇到未知 `kid` 时会自动重新拉取 JWKS
- **时钟偏移容忍**：JWT 过期校验支持可配置 leeway（默认 30 秒）
- **JWKS 缓存**：按可配置 TTL 缓存 provider 公钥（默认 1 小时）

## 配置

```python
verifier = Verifier(
    trusted_providers=["www.modelscope.cn"],
    audience="hub_4abb08",
    jwks_urls={
        "www.modelscope.cn":
            "https://www.modelscope.cn/openapi/v1/agent_id/.well-known/agentid-jwks",
    },
    dpop_mode="disabled",
    cache_ttl=3600,            # JWKS 缓存 TTL，单位秒，默认 1 小时
    clock_skew_seconds=30,     # 时钟偏移容忍，默认 30 秒
)
```

## 文档

完整文档见 service SDK 指南：
[中文](https://github.com/agentscope-ai/agent-identity/blob/main/docs/agentid-service-sdk.zh.md) /
[English](https://github.com/agentscope-ai/agent-identity/blob/main/docs/agentid-service-sdk.md)。

更多背景见 [AgentID 仓库](https://github.com/agentscope-ai/agent-identity)。
