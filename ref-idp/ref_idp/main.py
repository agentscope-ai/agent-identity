"""AgentID reference IdP — FastAPI application."""

import os

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ref_idp.config import settings
from ref_idp.crypto.keys import compute_kid
from ref_idp.models.database import init_db
from ref_idp.routes import agents, auth, discovery, hub_apps, token

app = FastAPI(title="AgentID reference IdP", version="0.1.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mounted to mirror ModelScope's OpenAPI paths. Discovery + token live under
# /openapi/v1/agent_id (singular); CRUD under /openapi/v1 (router prefixes
# /agent_ids, /hub_apps). The auth router (dev principal bootstrap / OAuth)
# stays at /agentid — it has no ModelScope equivalent (ModelScope uses the
# user's account AccessToken).
app.include_router(discovery.router, prefix="/openapi/v1/agent_id")
app.include_router(token.router, prefix="/openapi/v1/agent_id")
app.include_router(agents.router, prefix="/openapi/v1")
app.include_router(hub_apps.router, prefix="/openapi/v1")
app.include_router(auth.router, prefix="/agentid")


@app.on_event("startup")
async def startup():
    # Initialize database
    await init_db()

    # Load or generate IdP signing keypair
    key_path = settings.idp_signing_key_path
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(key_path, "wb") as f:
            f.write(pem)

    # Compute kid from public key
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = compute_kid(pub_bytes)

    # Store on app state
    app.state.idp_private_key = private_key
    app.state.idp_kid = kid
    app.state.idp_domain = settings.idp_domain
    app.state.idp_base_url = settings.idp_base_url
    app.state.token_ttl_seconds = settings.token_ttl_seconds
    app.state.dpop_enabled = settings.dpop_enabled
