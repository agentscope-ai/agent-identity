"""Application configuration."""

from dataclasses import dataclass, field


@dataclass
class Settings:
    database_url: str = "sqlite+aiosqlite:///./aip_idp.db"
    idp_domain: str = "localhost"
    idp_signing_key_path: str = "./idp_signing_key.pem"
    token_ttl_seconds: int = 4 * 60 * 60  # 4 hours
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    github_client_id: str = ""  # GitHub OAuth App client ID
    github_client_secret: str = ""  # GitHub OAuth App client secret (for web auth code flow)


settings = Settings()
