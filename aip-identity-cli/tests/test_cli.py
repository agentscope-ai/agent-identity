"""Basic tests for AIP CLI structure."""

from typer.testing import CliRunner

from aip_identity_cli.main import app


runner = CliRunner()


def test_app_has_init_command():
    """Verify the init command is registered."""
    result = runner.invoke(app, ["init", "--help"])
    assert result.exit_code == 0
    assert "Initialize AIP CLI" in result.output


def test_app_has_agent_group():
    """Verify the agent command group is registered."""
    result = runner.invoke(app, ["agent", "--help"])
    assert result.exit_code == 0
    assert "create" in result.output
    assert "list" in result.output
    assert "token" in result.output


def test_agent_create_help():
    """Verify agent create has --name option."""
    result = runner.invoke(app, ["agent", "create", "--help"])
    assert result.exit_code == 0
    assert "--name" in result.output


def test_agent_token_help():
    """Verify agent token has --name and --audience options."""
    result = runner.invoke(app, ["agent", "token", "--help"])
    assert result.exit_code == 0
    assert "--name" in result.output
    assert "--audience" in result.output


def test_crypto_generate_keypair():
    """Verify keypair generation produces correct sizes."""
    from aip_identity_cli.crypto import generate_keypair, compute_kid

    priv, pub = generate_keypair()
    assert len(priv) == 32
    assert len(pub) == 32
    kid = compute_kid(pub)
    assert len(kid) == 16


def test_crypto_sign_and_verify():
    """Verify signing produces a valid hex signature."""
    from aip_identity_cli.crypto import generate_keypair, sign_token_request, compute_kid

    priv, pub = generate_keypair()
    kid = compute_kid(pub)
    sig = sign_token_request(priv, "agent-123", kid, "https://example.com", "1700000000")
    # Ed25519 signature is 64 bytes = 128 hex chars
    assert len(sig) == 128


def test_config_paths():
    """Verify config path helpers return expected locations."""
    from pathlib import Path
    from aip_identity_cli.config import AIP_HOME, get_config_path, get_agent_dir

    assert get_config_path() == AIP_HOME / "config.json"
    assert get_agent_dir("myagent") == AIP_HOME / "agents" / "myagent"
