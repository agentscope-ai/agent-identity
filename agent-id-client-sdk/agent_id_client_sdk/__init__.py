from .identity import Identity
from .client import Client
from .manage import (
    generate_keypair,
    compute_kid,
    sign_token_request,
    save_config,
    load_config,
    get_config_path,
    get_agent_dir,
    save_agent,
    load_private_key,
    register_agent,
    create_agent,
    device_flow_init,
    device_flow_poll,
    direct_login,
    RegisteredAgent,
    DeviceFlowChallenge,
    PrincipalCredentials,
)

__all__ = [
    "Identity",
    "Client",
    "generate_keypair",
    "compute_kid",
    "sign_token_request",
    "save_config",
    "load_config",
    "get_config_path",
    "get_agent_dir",
    "save_agent",
    "load_private_key",
    "register_agent",
    "create_agent",
    "device_flow_init",
    "device_flow_poll",
    "direct_login",
    "RegisteredAgent",
    "DeviceFlowChallenge",
    "PrincipalCredentials",
]

# v0.1 compatibility aliases — to be removed in v1.0.
AIPIdentity = Identity
AIPClient = Client
