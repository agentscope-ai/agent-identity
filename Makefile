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

.PHONY: help hub agent

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk -F':.*?##' '{printf "  %-20s %s\n", $$1, $$2}'
	@echo "  agent <sub> [args]   Run agent.py <whoami|demo|book|delete|trade> [positional args]"

hub: ## Start demo-hub on :8001 (IDP=local|pre|prod)
	cd $(HUB_DIR) && $(ENV) uvicorn hub:app --port 8001

agent:
	cd $(AGENT_DIR) && $(ENV) python agent.py $(AGENT_GOALS)
