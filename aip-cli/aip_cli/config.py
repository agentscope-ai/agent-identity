"""Configuration management for AIP CLI."""

import json
from pathlib import Path


AIP_HOME = Path.home() / ".aip"


def get_config_path() -> Path:
    """Return the path to the config file."""
    return AIP_HOME / "config.json"


def get_agent_dir(name: str) -> Path:
    """Return the directory for a given agent."""
    return AIP_HOME / "agents" / name


def load_config() -> dict:
    """Load config from ~/.aip/config.json.

    Returns a dict with keys: idp_url, principal_id, management_token.
    Raises FileNotFoundError if config does not exist.
    """
    config_path = get_config_path()
    if not config_path.exists():
        raise FileNotFoundError(
            "AIP CLI not initialized. Run 'aip init' first."
        )
    with open(config_path) as f:
        return json.load(f)


def save_config(idp_url: str, principal_id: str, management_token: str) -> None:
    """Save config to ~/.aip/config.json."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "idp_url": idp_url,
        "principal_id": principal_id,
        "management_token": management_token,
    }
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)
