"""agent-id init command — authenticate with an IdP.

Default: GitHub OAuth Device Flow (production).
--dev mode: direct registration without OAuth (local development/testing).
"""

import time
import webbrowser
from typing import Optional

import typer

from agent_id_client_sdk.manage import (
    get_config_path,
    save_config,
    device_flow_init,
    device_flow_poll,
    direct_login,
)


def _init_dev(base: str, name: str) -> dict:
    """Dev mode: direct register/login without OAuth verification."""
    try:
        creds = direct_login(base, name)
    except Exception as e:
        typer.echo(f"Error contacting IdP: {e}", err=True)
        raise typer.Exit(code=1)
    return {
        "principal_id": creds.principal_id,
        "management_token": creds.management_token,
        "external_id": creds.external_id,
        "name": creds.name,
    }


def _init_github(base: str) -> dict:
    """Production mode: GitHub OAuth Device Flow."""
    try:
        challenge = device_flow_init(base)
    except Exception as e:
        typer.echo(f"Error contacting IdP: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"\nPlease visit: {challenge.verification_uri}")
    typer.echo(f"Enter code:   {challenge.user_code}\n")

    if typer.confirm("Open browser?", default=True):
        webbrowser.open(challenge.verification_uri)

    typer.echo("Waiting for authorization...", nl=False)

    interval = challenge.interval
    while True:
        time.sleep(interval)

        try:
            creds = device_flow_poll(base, challenge.device_code)
        except Exception as e:
            typer.echo(f"\nError polling IdP: {e}", err=True)
            raise typer.Exit(code=1)

        if creds is None:
            typer.echo(".", nl=False)
            continue

        typer.echo()  # newline after dots
        return {
            "principal_id": creds.principal_id,
            "management_token": creds.management_token,
            "external_id": creds.external_id,
            "name": creds.name,
        }


def init(
    provider: str = typer.Option(
        "http://localhost:8000",
        "--provider",
        help="IdP provider URL",
    ),
    dev: bool = typer.Option(
        False,
        "--dev",
        help="Dev mode: skip OAuth, register directly (no identity verification)",
    ),
    name: Optional[str] = typer.Option(
        None,
        "--name",
        help="Principal name (required in --dev mode)",
    ),
) -> None:
    """Initialize AgentID CLI — authenticate with an identity provider."""
    config_path = get_config_path()
    if config_path.exists():
        overwrite = typer.confirm("AgentID CLI is already initialized. Overwrite?")
        if not overwrite:
            raise typer.Abort()

    base = provider.rstrip("/")

    if dev:
        if not name:
            typer.echo("--name is required in --dev mode.", err=True)
            raise typer.Exit(code=1)
        result = _init_dev(base, name)
        external_id = name
        display_name = name
    else:
        result = _init_github(base)
        external_id = result.get("external_id", "")
        display_name = external_id or result.get("name", "")

    principal_name = result.get("name", display_name)

    save_config(
        idp_url=base,
        principal_id=result["principal_id"],
        management_token=result["management_token"],
        external_id=external_id,
        name=principal_name,
    )

    typer.echo(f"\u2713 Logged in as {display_name} on {provider}")
