# AIP Reference Implementation — Demo

## Quick Start

### 1. Install packages (from repo root)

```
pip install -e aip-idp/
pip install -e aip-cli/
pip install -e aip-sdk/
pip install -e aip-verify/
```

### 2. Start the IdP

```
cd aip-idp
uvicorn app.main:app --port 8000
```

### 3. Start the demo hub

```
cd examples/demo-hub
uvicorn hub:app --port 8001
```

### 4. Create an identity (in a new terminal)

```
# Register as a principal
aip init --name alice --provider http://localhost:8000

# Create an agent
aip agent create --name demo-agent
```

### 5. Run the demo agent

```
cd examples/demo-agent
python agent.py
```

## What happens

1. `aip init` registers you as a principal with the IdP
2. `aip agent create` generates an Ed25519 keypair and registers the public key with the IdP
3. The demo agent loads the private key, signs a token request, gets a JWT from the IdP
4. The demo agent sends the JWT to the hub
5. The hub verifies the JWT against the IdP's public key (fetched and cached from `/.well-known/aip-jwks`)
6. The hub returns the agent's identity — proving the full auth loop works
