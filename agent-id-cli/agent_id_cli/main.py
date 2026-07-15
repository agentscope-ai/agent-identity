"""AgentID CLI — manage agent identities from the command line.

PARKED / not maintained. This CLI targets the legacy native IdP API
(``/agentid/*``); neither the live ModelScope IdP nor the current ``ref-idp``
serve those paths — both use ``/openapi/v1/agent_id/*``. Kept for reference
only; no new PyPI releases. A provider-aware rewrite (a thin wrapper over
``ModelScopeProvider`` + ``agent-id-client-sdk``) is planned. For ModelScope
provisioning today, use the ModelScope console or ``agent_id_client_sdk.providers``.
"""

import typer

from agent_id_cli.commands.init import init
from agent_id_cli.commands.agent import app as agent_app

app = typer.Typer(help="AgentID CLI — manage agent identities")
app.command("init")(init)
app.add_typer(agent_app, name="agent")

if __name__ == "__main__":
    app()
