"""AgentID CLI — manage agent identities from the command line."""

import typer

from agent_id_cli.commands.init import init
from agent_id_cli.commands.agent import app as agent_app

app = typer.Typer(help="AgentID CLI — manage agent identities")
app.command("init")(init)
app.add_typer(agent_app, name="agent")

if __name__ == "__main__":
    app()
