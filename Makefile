IMAGE_NAME ?= moj-github-discovery:audit-cli-poc
ENV_FILE ?= docker-audit-cli/.env
AUDIT_ARGS ?= --scripts list_repos
AUDIT_SMOKE_ARGS ?= --scripts alert_metrics --repo ministryofjustice/moj-github-discovery
DOCKER_PLATFORM ?= linux/amd64

.PHONY: audit-cli audit-cli-build audit-cli-run audit-cli-smoke audit-cli-check-env

audit-cli: audit-cli-build audit-cli-run

audit-cli-build:
	docker build --platform $(DOCKER_PLATFORM) -f docker-audit-cli/Dockerfile -t $(IMAGE_NAME) .

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
		$(IMAGE_NAME) $$args

# Lightweight smoke check: one script, one repo.
audit-cli-smoke:
	@$(MAKE) audit-cli-run AUDIT_ARGS="$(AUDIT_SMOKE_ARGS)"