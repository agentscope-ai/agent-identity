"""
Demo: A minimal hub that verifies AIP tokens.

Start: uvicorn hub:app --port 8001
"""
from fastapi import FastAPI, Request, HTTPException
from aip_verify import AIPVerifier

app = FastAPI(title="Demo Hub")

# Trust the local IdP. In production, use real provider domains.
verifier = AIPVerifier(
    trusted_providers=["localhost"],
    audience="http://localhost:8001",
    provider_urls={"localhost": "http://localhost:8000"},  # local dev override
)


async def get_agent(request: Request):
    """Extract and verify the AIP agent from the request."""
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(401, "Missing Authorization header")
    try:
        agent = await verifier.verify(auth)
        return agent
    except Exception as e:
        raise HTTPException(401, str(e))


@app.get("/api/whoami")
async def whoami(request: Request):
    agent = await get_agent(request)
    return {
        "agent_id": agent.agent_id,
        "agent_name": agent.agent_name,
        "principal": agent.principal,
        "capabilities": agent.capabilities,
        "message": f"Welcome, {agent.agent_name}!",
    }


@app.get("/api/ping")
async def ping(request: Request):
    agent = await get_agent(request)
    return {
        "agent_id": agent.agent_id,
        "status": "pong",
    }


@app.get("/.well-known/aip-hub")
async def hub_discovery():
    return {
        "service_id": "http://localhost:8001",
        "trusted_providers": ["localhost"],
        "local_mode": False,
        "aip_version": "1.0",
    }
