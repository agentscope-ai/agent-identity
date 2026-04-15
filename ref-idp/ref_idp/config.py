"""Application configuration."""

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    database_url: str = "sqlite+aiosqlite:///./ref_idp.db"
    idp_domain: str = "localhost"
    idp_base_url: str = ""  # Full base URL; derived from idp_domain if empty
    idp_signing_key_path: str = "./idp_signing_key.pem"
    token_ttl_seconds: int = 4 * 60 * 60  # 4 hours
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    github_client_id: str = ""  # GitHub OAuth App client ID
    github_client_secret: str = (
        ""  # GitHub OAuth App client secret (for web auth code flow)
    )

    def __post_init__(self):
        """Override defaults from environment variables."""
        env_map = {
            "AIP_DATABASE_URL": "database_url",
            "AIP_IDP_DOMAIN": "idp_domain",
            "AIP_IDP_BASE_URL": "idp_base_url",
            "AIP_IDP_SIGNING_KEY_PATH": "idp_signing_key_path",
            "AIP_TOKEN_TTL_SECONDS": "token_ttl_seconds",
            "AIP_GITHUB_CLIENT_ID": "github_client_id",
            "AIP_GITHUB_CLIENT_SECRET": "github_client_secret",
        }
        for env_var, attr in env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                if attr == "token_ttl_seconds":
                    value = int(value)
                setattr(self, attr, value)

        # Derive base_url from domain if not explicitly set.
        if not self.idp_base_url:
            if self.idp_domain == "localhost":
                self.idp_base_url = "http://localhost:8000"
            else:
                self.idp_base_url = f"https://{self.idp_domain}"


settings = Settings()
