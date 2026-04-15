"""aip agent command group — create, list, and get tokens for agents."""

import json
import time
from pathlib import Path

import typer

from aip_identity_sdk.identity import AIPIdentity
from aip_identity_sdk.manage import (
    get_agent_dir,
    create_agent,
    load_private_key,
    sign_token_request,
)
import httpx

app = typer.Typer(help="Manage agents")


@app.command("create")
def create(
    name: str = typer.Option(..., "--name", help="Agent name"),
) -> None:
    """Create a new agent identity."""
    try:
        registered, agent_dir = create_agent(name)
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.echo(f"Error creating agent: {e}", err=True)
        raise typer.Exit(code=1)

    # Read back metadata for display
    with open(agent_dir / "agent.json") as f:
        meta = json.load(f)

    external_id = meta.get("principal_external_id", "")
    principal_name = meta.get("principal_name", "")

    typer.echo(f"\u2713 Agent created: {registered.agent_id}")
    typer.echo(
        f"  Principal: {external_id or meta.get('principal_id', '')}"
        + (
            f" ({principal_name})"
            if principal_name and principal_name != external_id
            else ""
        )
    )
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

    # Derive IdP URL from agent_id domain
    idp_url = AIPIdentity._idp_url_from_agent_id(meta["agent_id"])
    url = f"{idp_url}/aip/token"
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
