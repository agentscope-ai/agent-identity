"""aip init command — authenticate with an IdP.

Default: GitHub OAuth Device Flow (production).
--dev mode: direct registration without OAuth (local development/testing).
"""

import time
import webbrowser
from typing import Optional

import httpx
import typer

from aip_cli.config import get_config_path, save_config


def _init_dev(base: str, name: str) -> dict:
    """Dev mode: direct register/login without OAuth verification."""
    try:
        resp = httpx.post(
            f"{base}/aip/auth/login",
            json={"external_id": name},
        )
        if resp.status_code == 404:
            resp = httpx.post(
                f"{base}/aip/auth/register",
                json={"type": "human", "name": name, "external_id": name},
            )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        typer.echo(f"Error contacting IdP: {e}", err=True)
        raise typer.Exit(code=1)
    return resp.json()


def _init_github(base: str) -> dict:
    """Production mode: GitHub OAuth Device Flow."""
    try:
        resp = httpx.post(f"{base}/aip/auth/device")
        if resp.status_code == 501:
            typer.echo(
                "GitHub OAuth is not configured on this IdP.\n"
                "Use --dev mode for local testing, or configure "
                "github_client_id on the IdP.",
                err=True,
            )
            raise typer.Exit(code=1)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        typer.echo(f"Error contacting IdP: {e}", err=True)
        raise typer.Exit(code=1)

    data = resp.json()
    device_code = data["device_code"]
    user_code = data["user_code"]
    verification_uri = data["verification_uri"]
    interval = data.get("interval", 5)

    typer.echo(f"\nPlease visit: {verification_uri}")
    typer.echo(f"Enter code:   {user_code}\n")

    if typer.confirm("Open browser?", default=True):
        webbrowser.open(verification_uri)

    typer.echo("Waiting for authorization...", nl=False)

    while True:
        time.sleep(interval)

        try:
            resp = httpx.post(
                f"{base}/aip/auth/device/token",
                json={"device_code": device_code},
            )
        except httpx.HTTPError as e:
            typer.echo(f"\nError polling IdP: {e}", err=True)
            raise typer.Exit(code=1)

        if resp.status_code == 404:
            typer.echo(
                "\nDevice code expired. Please run `aip init` again.", err=True,
            )
            raise typer.Exit(code=1)

        if resp.status_code >= 400:
            typer.echo(f"\nError: {resp.text}", err=True)
            raise typer.Exit(code=1)

        result = resp.json()

        if "error" in result:
            if result["error"] == "slow_down":
                interval += 5
            typer.echo(".", nl=False)
            continue

        typer.echo()  # newline after dots
        return result


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
    """Initialize AIP CLI — authenticate with an identity provider."""
    config_path = get_config_path()
    if config_path.exists():
        overwrite = typer.confirm(
            "AIP CLI is already initialized. Overwrite?"
        )
        if not overwrite:
            raise typer.Abort()

    base = provider.rstrip("/")

    if dev:
        if not name:
            typer.echo("--name is required in --dev mode.", err=True)
            raise typer.Exit(code=1)
        result = _init_dev(base, name)
        display_name = name
    else:
        result = _init_github(base)
        display_name = result.get("external_id") or result.get("name", "")

    save_config(
        idp_url=base,
        principal_id=result["principal_id"],
        management_token=result["management_token"],
    )

    typer.echo(f"\u2713 Logged in as {display_name} on {provider}")
