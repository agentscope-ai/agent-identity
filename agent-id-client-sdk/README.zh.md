# agent-id-client-sdk

AgentID Client SDK 是 Agent 侧 SDK，用于让 AI Agent 从兼容协议的 IdP 获取
AgentID JWT，并访问 Agent身份互联应用（Agent Identity Connected App, IDA）
服务。本包包含面向已上线 ModelScope IdP 的 provider adapter。

英文版：[README.md](README.md)

## 安装

```bash
pip install agent-id-client-sdk
```

## 快速开始

```python
from agent_id_client_sdk import Client, Identity

# 从已保存的 profile、环境变量或 zip bundle 加载 agent identity。
identity = Identity.from_profile("my-agent")

# audience 是 IDA 应用注册得到的 client_id。
client = Client(identity, default_audience="hub_4abb08")

token = await client.get_token()
response = await client.get("https://ida.example.com/api/data")
response.raise_for_status()
```

## 文档

完整文档见 client SDK 指南：
[中文](https://github.com/agentscope-ai/agent-identity/blob/main/docs/agentid-client-sdk.zh.md) /
[English](https://github.com/agentscope-ai/agent-identity/blob/main/docs/agentid-client-sdk.md)。

更多背景见 [AgentID 仓库](https://github.com/agentscope-ai/agent-identity)。
