SHELL := /bin/sh
.SHELLFLAGS := -eu -c

TARGET_DIR := target
OUTPUT_DIR := output
APPSEC_LANGS ?= auto
# Operator setting, never an MCP input: 1 scans with --network none from data fetched earlier by
# `make offline-data` into OFFLINE_DIR (mounted read-only); 0 fetches rules and advisories live.
APPSEC_OFFLINE ?= 0
OFFLINE_DIR := offline-data

ifeq ($(filter 0 1,$(APPSEC_OFFLINE)),)
$(error APPSEC_OFFLINE must be 0 or 1, got '$(APPSEC_OFFLINE)')
endif

ifeq ($(APPSEC_OFFLINE),1)
SEMGREP_CONFIG := $(OFFLINE_DIR)/semgrep/p-default.yml
TRIVY_DATA_FLAGS := --cache-dir $(OFFLINE_DIR)/trivy --skip-db-update --skip-java-db-update --skip-check-update --offline-scan
else
SEMGREP_CONFIG := p/default
TRIVY_DATA_FLAGS :=
endif

SEMGREP_REPORT := $(OUTPUT_DIR)/semgrep.json
SUPPRESSIONS_REPORT := $(OUTPUT_DIR)/suppressions.json
GITLEAKS_REPORT := $(OUTPUT_DIR)/gitleaks.json
OSV_REPORT := $(OUTPUT_DIR)/osv.json
TRIVY_REPORT := $(OUTPUT_DIR)/trivy.json
CHECKOV_REPORT := $(OUTPUT_DIR)/checkov.json
LANGUAGE_PROFILE_REPORT := $(OUTPUT_DIR)/language-profile.json
SBOM_REPORT := $(OUTPUT_DIR)/sbom.cdx.json

# Write output/run-manifest.json for the task that was requested, not for each prerequisite,
# so appsec-full produces one manifest covering all of its reports.
define manifest
$(if $(filter $@,$(MAKECMDGOALS)),@APPSEC_OFFLINE="$(APPSEC_OFFLINE)" ./scripts/write-manifest.py "$(TARGET_DIR)" "$(OUTPUT_DIR)" "$@")
endef

.PHONY: appsec-full security-semgrep security-gitleaks security-osv security-trivy security-checkov security-language \
        supply-chain-sbom toolbox-check toolbox-versions offline-data test lint test-image image

appsec-full: security-semgrep security-gitleaks security-osv security-trivy security-checkov security-language supply-chain-sbom ## Run the complete passive AppSec evidence bundle
	$(manifest)

security-semgrep: toolbox-check ## Run Semgrep SAST and inventory suppression markers in the mounted target
	@rm -f "$(SEMGREP_REPORT)" "$(SUPPRESSIONS_REPORT)"
	@./scripts/find-suppressions.py "$(TARGET_DIR)" "$(OUTPUT_DIR)"
	@semgrep scan \
		--config "$(SEMGREP_CONFIG)" \
		--metrics=off \
		--disable-version-check \
		--no-git-ignore \
		--x-ignore-semgrepignore-files \
		--disable-nosem \
		--json \
		--output "$(SEMGREP_REPORT)" \
		"$(TARGET_DIR)"
	$(manifest)

security-gitleaks: toolbox-check ## Scan the mounted working tree for secrets with Gitleaks
	@rm -f "$(GITLEAKS_REPORT)"
	@./scripts/run-gitleaks.sh "$(TARGET_DIR)" "$(GITLEAKS_REPORT)"
	$(manifest)

security-osv: toolbox-check ## Scan dependency metadata with OSV-Scanner without dependency resolution
	@rm -f "$(OSV_REPORT)"
	@APPSEC_OFFLINE="$(APPSEC_OFFLINE)" OFFLINE_DIR="$(OFFLINE_DIR)" ./scripts/run-osv.sh "$(TARGET_DIR)" "$(OSV_REPORT)"
	$(manifest)

security-trivy: toolbox-check ## Scan vulnerabilities, misconfigurations, secrets, and licenses with Trivy
	@rm -f "$(TRIVY_REPORT)"
	@trivy fs \
		--scanners vuln,misconfig,secret,license \
		--format json \
		--output "$(TRIVY_REPORT)" \
		--exit-code 0 \
		--no-progress \
		--skip-version-check \
		--ignorefile config/.trivyignore \
		$(TRIVY_DATA_FLAGS) \
		"$(TARGET_DIR)"
	$(manifest)

# --directory=PATH is one argv item on purpose: Checkov loads PATH/.checkov.yaml only when the
# flag and the path are separate arguments, and that file can name external checks to import.
security-checkov: toolbox-check ## Scan IaC and CI/CD configuration with Checkov
	@rm -f "$(CHECKOV_REPORT)"
	@checkov \
		--directory="$(TARGET_DIR)" \
		--framework argo_workflows arm bicep bitbucket_pipelines cloudformation dockerfile github_actions gitlab_ci helm kubernetes kustomize openapi serverless terraform terraform_plan \
		--output json \
		--quiet \
		--soft-fail \
		--skip-download \
		> "$(CHECKOV_REPORT)"
	$(manifest)

security-language: toolbox-check ## Run applicable language-specific passive SAST profiles
	@rm -f "$(LANGUAGE_PROFILE_REPORT)"
	@APPSEC_LANGS="$(APPSEC_LANGS)" ./scripts/run-language-profiles.py "$(TARGET_DIR)" "$(OUTPUT_DIR)"
	$(manifest)

supply-chain-sbom: toolbox-check ## Generate a CycloneDX JSON SBOM with Syft
	@rm -f "$(SBOM_REPORT)"
	@SYFT_CHECK_FOR_APP_UPDATE=false syft scan "dir:$(TARGET_DIR)" \
		--quiet \
		--output "cyclonedx-json=$(SBOM_REPORT)"
	$(manifest)

# Maintenance targets are explicitly disabled from MCP exposure in .makefile-mcp.yaml.
toolbox-check:
	@test -d "$(TARGET_DIR)" || { echo "missing $(TARGET_DIR)/; mount the audited repository there" >&2; exit 2; }
	@mkdir -p "$(OUTPUT_DIR)"
	@test "$(APPSEC_OFFLINE)" = 0 || test -f "$(OFFLINE_DIR)/offline-data.json" \
		|| { echo "APPSEC_OFFLINE=1 needs $(OFFLINE_DIR)/; run make offline-data first" >&2; exit 2; }

# Operator-only, with network access: fetch the data APPSEC_OFFLINE=1 scans use. Disabled in MCP.
offline-data:
	@./scripts/fetch-offline-data.py "$(OFFLINE_DIR)"

# Fails if any scanner is missing or cannot execute; the version lines below use pipes,
# which would otherwise hide a broken tool.
toolbox-versions:
	@for tool in makefile-mcp semgrep gitleaks osv-scanner trivy checkov bandit njsscan gosec findsecbugs go syft; do \
		command -v "$$tool" >/dev/null || { echo "missing scanner: $$tool" >&2; exit 1; }; \
	done
	@printf 'makefile-mcp: '; makefile-mcp --version
	@printf 'semgrep: '; semgrep --version
	@printf 'gitleaks: '; gitleaks version
	@printf 'osv-scanner: '; osv-scanner --version
	@printf 'trivy: '; trivy --version | head -n 1
	@printf 'checkov: '; checkov --version
	@printf 'bandit: '; bandit --version | head -n 1
	@printf 'njsscan: '; njsscan --version
	@printf 'gosec: '; gosec -version 2>&1 | head -n 1
	@printf 'findsecbugs: '; findsecbugs -version >/dev/null 2>&1 && basename /opt/findsecbugs/lib/findsecbugs-plugin-*.jar .jar
	@printf 'go: '; go version
	@printf 'syft: '; syft version | head -n 1

# Unit tests and lint need pytest and ruff (pipx install pytest==8.4.2 ruff==0.14.0).
PYTEST ?= pytest
RUFF ?= ruff

test: lint
	@$(PYTEST) -q
	@./tests/smoke.sh

lint:
	@$(RUFF) check scripts tests/unit
	@$(RUFF) format --check scripts tests/unit

# Known-positive run of the real image against examples/vulnerable-sample (Docker + network).
test-image:
	@./tests/image.sh

image:
	@docker build -t appsec-toolbox-mcp:dev .
