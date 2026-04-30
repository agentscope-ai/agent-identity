# Demo control surface.
#
# Usage:
#   make hub                                    # demo-hub against local IdP
#   make hub IDP=pre                            # demo-hub against pre.agent-id.live
#   make hub IDP=prod
#
#   make agent whoami
#   make agent demo
#   make agent book   SFO 299
#   make agent delete /tmp/foo
#   make agent trade  BTC/USD 1000 buy
#
#   ...append IDP=pre / IDP=prod to switch identity (it's a Make variable
#   assignment, so it goes anywhere on the line).

IDP ?= local

HUB_DIR := examples/demo-hub
AGENT_DIR := examples/demo-agent

ENV := AIP_IDP=$(IDP)

# `make agent <sub> [args...]` — pass everything after `agent` straight to
# agent.py, and turn each word into a no-op target so Make doesn't try to
# build them as files.
ifeq (agent,$(firstword $(MAKECMDGOALS)))
  AGENT_GOALS := $(filter-out agent,$(MAKECMDGOALS))
  $(eval $(AGENT_GOALS):;@:)
endif

.PHONY: help hub agent stack stack-up

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk -F':.*?##' '{printf "  %-20s %s\n", $$1, $$2}'
	@echo "  agent <sub> [args]   Run agent.py <whoami|demo|book|delete|trade> [positional args]"

hub: ## Start demo-hub on :8001 (IDP=local|pre|prod)
	cd $(HUB_DIR) && $(ENV) uvicorn hub:app --port 8001

agent:
	cd $(AGENT_DIR) && $(ENV) python agent.py $(AGENT_GOALS)

# ---------------------------------------------------------------------------
# Local 3-process stack orientation
# ---------------------------------------------------------------------------

stack: ## Print the local stack recipe (4 terminals)
	@echo "Local activity-tracking stack — run each in its own terminal:"
	@echo
	@echo "  T1   aip-idp       :8000   cd ~/dev/aip-idp        && make dev"
	@echo "  T2   aip-activity  :8002   cd ~/dev/aip-activity   && make dev-local-idp"
	@echo "  T3   demo-hub      :8001   make hub IDP=local"
	@echo "  T4   demo-agent    one-shot   make agent demo"
	@echo
	@echo "Verify each piece:"
	@echo "  curl http://localhost:8000/.well-known/aip-configuration | jq .activity_endpoint"
	@echo "  curl http://localhost:8002/health"
	@echo "  curl http://localhost:8001/.well-known/aip-hub"
	@echo
	@echo "Note: demo-hub does not yet wire up activity reporting (verifier"
	@echo "      ctor needs activity_api_key + hub_namespace). Until that's done,"
	@echo "      events from demo-hub won't reach aip-activity. The IdP/activity"
	@echo "      services themselves are exerciseable via direct curl."

stack-up: ## Same as 'stack' — alias
	@$(MAKE) stack
