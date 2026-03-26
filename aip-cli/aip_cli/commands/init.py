"""aip init command — register/login with an IdP."""

import typer
import httpx

from aip_cli.config import get_config_path, save_config


def init(
    provider: str = typer.Option(
        "http://localhost:8000",
        "--provider",
        help="IdP provider URL",
    ),
    name: str = typer.Option(
        ...,
        "--name",
        help="Principal name",
    ),
    type: str = typer.Option(
        "human",
        "--type",
        help="Principal type (human or org)",
    ),
) -> None:
    """Initialize AIP CLI — register or login with an identity provider."""
    config_path = get_config_path()
    if config_path.exists():
        overwrite = typer.confirm(
            "AIP CLI is already initialized. Overwrite?"
        )
        if not overwrite:
            raise typer.Abort()

    # Try login first, then register if not found
    base = provider.rstrip("/")
    try:
        resp = httpx.post(
            f"{base}/aip/auth/login",
            json={"external_id": name},
        )
        if resp.status_code == 404:
            # New principal — register
            resp = httpx.post(
                f"{base}/aip/auth/register",
                json={"type": type, "name": name, "external_id": name},
            )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        typer.echo(f"Error contacting IdP: {e}", err=True)
        raise typer.Exit(code=1)

    data = resp.json()
    principal_id = data["principal_id"]
    management_token = data["management_token"]

    save_config(
        idp_url=provider.rstrip("/"),
        principal_id=principal_id,
        management_token=management_token,
    )

    typer.echo(f"\u2713 Logged in as {name} on {provider}")
