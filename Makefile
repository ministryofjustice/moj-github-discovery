DASHBOARD_PORT ?= 8050
IMAGE_NAME_BASE ?= developer-experience-
IMAGE_NAME_CLI ?= $(IMAGE_NAME_BASE)audit-cli
IMAGE_NAME_DASHBOARD ?= $(IMAGE_NAME_BASE)audit-dashboard
ENV_FILE ?= docker-audit-cli/.env
AUDIT_ARGS ?= --scripts list_repos
AUDIT_SMOKE_ARGS ?= --scripts alert_metrics --repos ministryofjustice/moj-github-discovery
DOCKER_PLATFORM ?= linux/amd64

.PHONY: audit-cli audit-cli-build audit-cli-run audit-cli-smoke audit-cli-check-env audit-dashboard audit-dashboard-build audit-dashboard-run

#
# Audit-CLI: build and run the audit CLI in a Docker container.
#

audit-cli: audit-cli-build audit-cli-run

audit-cli-build:
	docker build --platform $(DOCKER_PLATFORM) -f docker-audit-cli/Dockerfile --target cli -t $(IMAGE_NAME_CLI) .

audit-cli-check-env:
	@if [ ! -f $(ENV_FILE) ]; then \
		echo "$(ENV_FILE) not found. Creating it from docker-audit-cli/.env.example"; \
		cp docker-audit-cli/.env.example $(ENV_FILE); \
		echo "Created $(ENV_FILE). Update it with real values before running again."; \
		exit 1; \
	fi

audit-cli-run: audit-cli-check-env
	@mkdir -p outputs internal
	@args="$(AUDIT_ARGS)"; \
	case "$$args" in run\ *) args="$${args#run }" ;; esac; \
	echo "Running audit CLI with args: $$args"; \
	docker run --rm \
		--platform $(DOCKER_PLATFORM) \
		--env-file $(ENV_FILE) \
		-v "$(PWD)/outputs:/app/outputs" \
		-v "$(PWD)/internal:/app/internal" \
		$(IMAGE_NAME_CLI) $$args

# Lightweight smoke check: one script, one repo.
audit-cli-smoke:
	@$(MAKE) audit-cli-run AUDIT_ARGS="$(AUDIT_SMOKE_ARGS)"

#
# Audit-CLI Dashboard: build and run a Dash web server for visualising audit data.
#

audit-dashboard: audit-dashboard-build audit-dashboard-run

audit-dashboard-build:
	docker build --platform $(DOCKER_PLATFORM) -f docker-audit-cli/Dockerfile --target dashboard -t $(IMAGE_NAME_DASHBOARD) .

audit-dashboard-run: 
	@mkdir -p internal
	@echo "Running audit dashboard on http://localhost:$(DASHBOARD_PORT)"
	docker run --rm \
		--platform $(DOCKER_PLATFORM) \
		-v "$(PWD)/internal:/app/internal" \
		-p $(DASHBOARD_PORT):$(DASHBOARD_PORT) \
		$(IMAGE_NAME_DASHBOARD)