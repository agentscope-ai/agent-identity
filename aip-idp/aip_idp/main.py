"""AIP Identity Provider - FastAPI application."""

import os

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aip_idp.config import settings
from aip_idp.crypto.keys import compute_kid
from aip_idp.models.database import init_db
from aip_idp.routes import agents, auth, discovery, token

app = FastAPI(title="AIP Identity Provider", version="0.1.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(discovery.router)
app.include_router(auth.router)
app.include_router(agents.router)
app.include_router(token.router)


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
    app.state.token_ttl_seconds = settings.token_ttl_seconds
