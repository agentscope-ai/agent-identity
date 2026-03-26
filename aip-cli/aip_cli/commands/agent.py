"""aip agent command group — create, list, and get tokens for agents."""

import json
import time
from pathlib import Path

import typer
import httpx

from aip_cli.config import load_config, get_agent_dir
from aip_cli.crypto import (
    generate_keypair,
    save_private_key,
    load_private_key,
    sign_token_request,
    compute_kid,
)

app = typer.Typer(help="Manage agents")


@app.command("create")
def create(
    name: str = typer.Option(..., "--name", help="Agent name"),
) -> None:
    """Create a new agent identity."""
    try:
        config = load_config()
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(code=1)

    # Generate keypair
    private_key_bytes, public_key_bytes = generate_keypair()
    kid = compute_kid(public_key_bytes)

    # Register agent with IdP
    url = f"{config['idp_url']}/aip/agents"
    payload = {
        "name": name,
        "public_key": public_key_bytes.hex(),
        "principal_id": config["principal_id"],
    }
    headers = {"Authorization": f"Bearer {config['management_token']}"}

    try:
        resp = httpx.post(url, json=payload, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        typer.echo(f"Error creating agent: {e}", err=True)
        raise typer.Exit(code=1)

    data = resp.json()
    agent_id = data["agent_id"]

    # Save private key
    agent_dir = get_agent_dir(name)
    agent_dir.mkdir(parents=True, exist_ok=True)
    save_private_key(agent_dir / "private_key", private_key_bytes)

    # Save agent metadata
    agent_meta = {
        "agent_id": agent_id,
        "kid": kid,
        "name": name,
        "idp_url": config["idp_url"],
    }
    with open(agent_dir / "agent.json", "w") as f:
        json.dump(agent_meta, f, indent=2)

    typer.echo(f"\u2713 Agent created: {agent_id}")
    typer.echo(f"  Private key saved to {agent_dir}/")


@app.command("list")
def list_agents() -> None:
    """List all registered agents."""
    agents_dir = Path.home() / ".aip" / "agents"
    if not agents_dir.exists():
        typer.echo("No agents found.")
        return

    found = False
    for agent_dir in sorted(agents_dir.iterdir()):
        agent_json = agent_dir / "agent.json"
        if agent_json.exists():
            with open(agent_json) as f:
                meta = json.load(f)
            typer.echo(f"{meta['name']}  {meta['agent_id']}")
            found = True

    if not found:
        typer.echo("No agents found.")


@app.command("token")
def token(
    name: str = typer.Option(..., "--name", help="Agent name"),
    audience: str = typer.Option(..., "--audience", help="Target audience URL"),
) -> None:
    """Get a JWT token for an agent."""
    agent_dir = get_agent_dir(name)
    agent_json = agent_dir / "agent.json"

    if not agent_json.exists():
        typer.echo(f"Agent '{name}' not found. Run 'aip agent create' first.", err=True)
        raise typer.Exit(code=1)

    with open(agent_json) as f:
        meta = json.load(f)

    private_key_bytes = load_private_key(agent_dir / "private_key")
    timestamp = str(int(time.time()))
    signature = sign_token_request(
        private_key_bytes=private_key_bytes,
        agent_id=meta["agent_id"],
        kid=meta["kid"],
        audience=audience,
        timestamp=timestamp,
    )

    # Request token from IdP
    url = f"{meta['idp_url']}/aip/token"
    payload = {
        "agent_id": meta["agent_id"],
        "kid": meta["kid"],
        "audience": audience,
        "timestamp": timestamp,
        "signature": signature,
    }

    try:
        resp = httpx.post(url, json=payload)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        typer.echo(f"Error requesting token: {e}", err=True)
        raise typer.Exit(code=1)

    data = resp.json()
    typer.echo(data["token"])
