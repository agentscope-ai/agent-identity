"""
Demo: Autonomous agent authenticating with a hub using AIP.

Prerequisites:
  1. Start the IdP: cd ref-idp && uvicorn ref_idp.main:app --port 8000
  2. Start the demo hub: cd examples/demo-hub && uvicorn hub:app --port 8001
  3. Create an agent identity:
     aip init --provider http://localhost:8000 --dev --name alice
     aip agent create --name demo-agent
  4. Run this script: python agent.py
"""
import asyncio
from aip_identity_sdk import AIPIdentity, AIPClient


async def main():
    # Load identity from disk (created by CLI)
    identity = AIPIdentity.from_file("demo-agent")
    client = AIPClient(identity)

    hub_url = "http://localhost:8001"

    # Make an authenticated request
    response = await client.get(f"{hub_url}/api/whoami")
    print(f"Hub says: {response.json()}")

    # Make another request — token is cached and reused
    response = await client.get(f"{hub_url}/api/ping")
    print(f"Ping: {response.json()}")


if __name__ == "__main__":
    asyncio.run(main())
