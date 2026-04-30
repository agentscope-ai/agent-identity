"""Identity management — setup-time operations for principals and agents.

This module provides the core logic that both `aip-cli` and platform CLIs
(e.g., QwenPaw) use to register principals, create agents, and manage keys.

Typical usage:

    from agent_id_client_sdk.manage import (
        generate_keypair, compute_kid,
        register_agent, device_flow_init, device_flow_poll,
    )
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ---------------------------------------------------------------------------
# Key generation & utilities
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns (private_key_bytes, public_key_bytes), both raw 32 bytes.
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key.private_bytes_raw(), private_key.public_key().public_bytes_raw()


def compute_kid(public_key_bytes: bytes) -> str:
    """Compute key ID: first 16 hex chars of SHA-256(public_key)."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


def sign_token_request(
    private_key_bytes: bytes,
    agent_id: str,
    kid: str,
    audience: str,
    timestamp: str,
) -> str:
    """Sign a token request message. Returns hex-encoded Ed25519 signature."""
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    message = f"{agent_id}|{kid}|{audience}|{timestamp}".encode()
    return private_key.sign(message).hex()


# ---------------------------------------------------------------------------
# Local file management
# ---------------------------------------------------------------------------

AIP_HOME = Path(os.environ.get("AIP_HOME", Path.home() / ".aip"))


def get_config_path() -> Path:
    """Return path to the principal config file."""
    return AIP_HOME / "config.json"


def get_agent_dir(name: str) -> Path:
    """Return directory for a given agent."""
    return AIP_HOME / "agents" / name


def save_config(
    idp_url: str,
    principal_id: str,
    management_token: str,
    external_id: str = "",
    name: str = "",
) -> None:
    """Save principal config to ~/.aip/config.json."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "idp_url": idp_url,
        "principal_id": principal_id,
        "management_token": management_token,
        "external_id": external_id,
        "name": name,
    }
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)


def load_config() -> dict:
    """Load principal config from ~/.aip/config.json."""
    config_path = get_config_path()
    if not config_path.exists():
        raise FileNotFoundError("AIP not initialized. Run 'aip init' first.")
    with open(config_path) as f:
        return json.load(f)


def save_agent(
    name: str,
    agent_id: str,
    kid: str,
    private_key_bytes: bytes,
    idp_url: str = "",
    principal_id: str = "",
    principal_external_id: str = "",
    principal_name: str = "",
) -> Path:
    """Save agent identity (keypair + metadata) to ~/.aip/agents/{name}/.

    Returns the agent directory path.
    """
    agent_dir = get_agent_dir(name)
    agent_dir.mkdir(parents=True, exist_ok=True)

    # Private key (restricted permissions)
    key_path = agent_dir / "private_key"
    key_path.write_bytes(private_key_bytes)
    os.chmod(key_path, 0o600)

    meta = {
        "agent_id": agent_id,
        "kid": kid,
        "name": name,
        "idp_url": idp_url,
        "principal_id": principal_id,
        "principal_external_id": principal_external_id,
        "principal_name": principal_name,
    }
    with open(agent_dir / "agent.json", "w") as f:
        json.dump(meta, f, indent=2)

    return agent_dir


def load_private_key(path: Path) -> bytes:
    """Load raw 32-byte private key from file."""
    return Path(path).read_bytes()


# ---------------------------------------------------------------------------
# IdP registration API
# ---------------------------------------------------------------------------


@dataclass
class RegisteredAgent:
    """Result of registering an agent with an IdP."""

    agent_id: str
    kid: str


def register_agent(
    idp_url: str,
    name: str,
    public_key_hex: str,
    principal_id: str,
    management_token: str,
) -> RegisteredAgent:
    """Register an agent's public key with the IdP.

    Returns the assigned agent_id and kid.
    """
    resp = httpx.post(
        f"{idp_url}/aip/agents",
        json={
            "name": name,
            "public_key": public_key_hex,
            "principal_id": principal_id,
        },
        headers={"Authorization": f"Bearer {management_token}"},
    )
    resp.raise_for_status()
    data = resp.json()
    return RegisteredAgent(agent_id=data["agent_id"], kid=data["kid"])


def create_agent(
    name: str,
    idp_url: str | None = None,
    principal_id: str | None = None,
    management_token: str | None = None,
    principal_external_id: str | None = None,
    principal_name: str | None = None,
) -> tuple[RegisteredAgent, Path]:
    """Generate keypair, register with IdP, save locally.

    If idp_url/principal_id/management_token are not provided,
    they are loaded from ~/.aip/config.json.

    Returns (RegisteredAgent, agent_dir).
    """
    config = load_config()
    idp_url = idp_url or config["idp_url"]
    principal_id = principal_id or config["principal_id"]
    management_token = management_token or config["management_token"]
    principal_external_id = principal_external_id or config.get("external_id", "")
    principal_name = principal_name or config.get("name", "")

    private_key_bytes, public_key_bytes = generate_keypair()
    kid = compute_kid(public_key_bytes)

    registered = register_agent(
        idp_url=idp_url,
        name=name,
        public_key_hex=public_key_bytes.hex(),
        principal_id=principal_id,
        management_token=management_token,
    )

    agent_dir = save_agent(
        name=name,
        agent_id=registered.agent_id,
        kid=kid,
        private_key_bytes=private_key_bytes,
        idp_url=idp_url,
        principal_id=principal_id,
        principal_external_id=principal_external_id,
        principal_name=principal_name,
    )

    return registered, agent_dir


# ---------------------------------------------------------------------------
# Principal authentication (IdP device flow)
# ---------------------------------------------------------------------------


@dataclass
class DeviceFlowChallenge:
    """Returned by device_flow_init — display to the user."""

    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


@dataclass
class PrincipalCredentials:
    """Returned after successful authentication."""

    principal_id: str
    management_token: str
    external_id: str
    name: str


def device_flow_init(idp_url: str) -> DeviceFlowChallenge:
    """Start the OAuth device flow on the IdP.

    Returns a challenge the caller should display to the user.
    """
    resp = httpx.post(f"{idp_url}/aip/auth/device")
    resp.raise_for_status()
    data = resp.json()
    return DeviceFlowChallenge(
        device_code=data["device_code"],
        user_code=data["user_code"],
        verification_uri=data["verification_uri"],
        expires_in=data.get("expires_in", 900),
        interval=data.get("interval", 5),
    )


def device_flow_poll(idp_url: str, device_code: str) -> PrincipalCredentials | None:
    """Poll the IdP for device flow completion.

    Returns PrincipalCredentials on success, None if still pending.
    Raises httpx.HTTPStatusError on failure.
    """
    resp = httpx.post(
        f"{idp_url}/aip/auth/device/token",
        json={"device_code": device_code},
    )
    resp.raise_for_status()
    data = resp.json()

    if "error" in data:
        if data["error"] == "slow_down":
            return None  # caller should increase interval
        if data["error"] == "authorization_pending":
            return None
        raise RuntimeError(f"OAuth error: {data['error']}")

    return PrincipalCredentials(
        principal_id=data["principal_id"],
        management_token=data["management_token"],
        external_id=data.get("external_id", ""),
        name=data.get("name", ""),
    )


def direct_login(idp_url: str, name: str) -> PrincipalCredentials:
    """Dev mode: register/login without OAuth verification."""
    resp = httpx.post(
        f"{idp_url}/aip/auth/login",
        json={"external_id": name},
    )
    if resp.status_code == 404:
        resp = httpx.post(
            f"{idp_url}/aip/auth/register",
            json={"type": "human", "name": name, "external_id": name},
        )
    resp.raise_for_status()
    data = resp.json()
    return PrincipalCredentials(
        principal_id=data["principal_id"],
        management_token=data["management_token"],
        external_id=name,
        name=name,
    )
