"""ModelScope AgentID quickstart — provision → token → verify, fully offline.

Runs the exact ModelScope-shaped loop end-to-end against a LOCAL ``ref-idp``
(the ModelScope mirror), so it needs no network, no ModelScope AccessToken, and
no IP allowlist. The ONLY things that change for real ModelScope are the
``IDP_BASE`` URL (pre/prod) and a real AccessToken — the SDK calls are identical.

Steps:
  1. register a hub app           → client_id (the token audience)
  2. provision an agent           → agent_id + kid + private key (key never leaves)
  3. agent mints a short JWT      → agent-id-client-sdk (Client.get_token)
  4. hub verifies the JWT         → agent-id-service-sdk (Verifier.verify)

Prereq — a local ref-idp on :8000:

    pip install -e ref-idp/ agent-id-client-sdk/ agent-id-service-sdk/
    cd ref-idp && uvicorn ref_idp.main:app --port 8000

Then, from the repo root:  python examples/modelscope-quickstart/quickstart.py
"""

from __future__ import annotations

import asyncio

from agent_id_client_sdk import Client, Identity
from agent_id_client_sdk.providers import provision_agent
from agent_id_client_sdk.providers.modelscope import ModelScopeProvider
from agent_id_service_sdk import Verifier

# Local ref-idp (ModelScope mirror). For real ModelScope, use e.g.
#   IDP_BASE = "https://pre.modelscope.cn/openapi/v1"   (prod: www.modelscope.cn)
#   PROVIDER_HOST = "pre.modelscope.cn"
#   ACCESS_TOKEN = "<your ModelScope AccessToken>"
IDP_BASE = "http://localhost:8000/openapi/v1"
# Provider key = the issuer netloc (host[:port]). Real ModelScope has no port,
# so it's just "pre.modelscope.cn"; locally the port is part of it.
PROVIDER_HOST = "localhost:8000"
JWKS_URL = f"{IDP_BASE}/agent_id/.well-known/agentid-jwks"

# ref-idp's control plane accepts ANY non-empty bearer as the dev AccessToken
# (it stands in for a real ModelScope account token).
ACCESS_TOKEN = "dev-access-token"


async def main() -> None:
    provider = ModelScopeProvider(ACCESS_TOKEN, base_url=IDP_BASE)

    print("1. register a hub app → client_id (the audience the agent mints for)")
    hub = provider.create_hub_app(
        app_name="Quickstart Hub", app_homepage="https://hub.example.com"
    )
    print(f"   client_id = {hub.client_id}")

    print("\n2. provision an agent (keygen + register the public JWK)")
    registered, private_key = provision_agent(provider, "quickstart-agent", save=False)
    print(f"   agent_id  = {registered.agent_id}")
    print(f"   kid       = {registered.kid}")
    # NOTE: against a local ref-idp the agent_id is aip:localhost:... ; real
    # ModelScope issues agent_id:modelscope:... . The SDK signs it verbatim, so
    # the runtime path is identical either way.

    print("\n3. agent mints a short-lived JWT for the hub audience")
    identity = Identity(
        agent_id=registered.agent_id,
        kid=registered.kid,
        private_key_bytes=private_key,
        idp_url=IDP_BASE,
    )
    # dpop=False: ModelScope tokens carry no cnf.jkt, so plain Bearer.
    client = Client(identity, default_audience=hub.client_id, dpop=False)
    token = await client.get_token()
    print(f"   token ({len(token)} chars): {token[:32]}…")

    print("\n4. hub verifies the JWT against the IdP's JWKS")
    verifier = Verifier(
        trusted_providers=[PROVIDER_HOST],
        audience=hub.client_id,
        jwks_urls={PROVIDER_HOST: JWKS_URL},
        dpop_mode="disabled",
    )
    verified = await verifier.verify(f"Bearer {token}")
    print(f"   verified agent_id = {verified.agent_id}")
    assert verified.agent_id == registered.agent_id, "verified sub != provisioned id"

    print(
        "\n✓ provision → token → verify OK against local ref-idp.\n"
        "  Swap IDP_BASE / PROVIDER_HOST / ACCESS_TOKEN for real ModelScope and"
        " the SDK calls are unchanged."
    )


if __name__ == "__main__":
    asyncio.run(main())
