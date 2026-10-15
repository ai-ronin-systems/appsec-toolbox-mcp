SHELL := /bin/sh
.SHELLFLAGS := -eu -c

TARGET_DIR := target
OUTPUT_DIR := output
APPSEC_LANGS ?= auto

SEMGREP_REPORT := $(OUTPUT_DIR)/semgrep.json
GITLEAKS_REPORT := $(OUTPUT_DIR)/gitleaks.json
OSV_REPORT := $(OUTPUT_DIR)/osv.json
TRIVY_REPORT := $(OUTPUT_DIR)/trivy.json
CHECKOV_REPORT := $(OUTPUT_DIR)/checkov.json
LANGUAGE_PROFILE_REPORT := $(OUTPUT_DIR)/language-profile.json
SBOM_REPORT := $(OUTPUT_DIR)/sbom.cdx.json

.PHONY: appsec-full security-semgrep security-gitleaks security-osv security-trivy security-checkov security-language \
        supply-chain-sbom toolbox-check toolbox-versions test image

appsec-full: security-semgrep security-gitleaks security-osv security-trivy security-checkov security-language supply-chain-sbom ## Run the complete passive AppSec evidence bundle

security-semgrep: toolbox-check ## Run Semgrep SAST against the mounted target
	@rm -f "$(SEMGREP_REPORT)"
	@semgrep scan \
		--config auto \
		--metrics=off \
		--disable-version-check \
		--no-git-ignore \
		--json \
		--output "$(SEMGREP_REPORT)" \
		"$(TARGET_DIR)"

security-gitleaks: toolbox-check ## Scan the mounted working tree for secrets with Gitleaks
	@rm -f "$(GITLEAKS_REPORT)"
	@gitleaks dir \
		--no-banner \
		--redact \
		--config config/gitleaks.toml \
		--exit-code 0 \
		--report-format json \
		--report-path "$(GITLEAKS_REPORT)" \
		"$(TARGET_DIR)"

security-osv: toolbox-check ## Scan dependency metadata with OSV-Scanner without dependency resolution
	@rm -f "$(OSV_REPORT)"
	@./scripts/run-osv.sh "$(TARGET_DIR)" "$(OSV_REPORT)"

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
		"$(TARGET_DIR)"

security-checkov: toolbox-check ## Scan IaC and CI/CD configuration with Checkov
	@rm -f "$(CHECKOV_REPORT)"
	@checkov \
		--directory "$(TARGET_DIR)" \
		--framework argo_workflows arm bicep bitbucket_pipelines cloudformation dockerfile github_actions gitlab_ci helm kubernetes kustomize openapi serverless terraform terraform_plan \
		--output json \
		--quiet \
		--soft-fail \
		> "$(CHECKOV_REPORT)"

security-language: toolbox-check ## Run applicable language-specific passive SAST profiles
	@rm -f "$(LANGUAGE_PROFILE_REPORT)"
	@APPSEC_LANGS="$(APPSEC_LANGS)" ./scripts/run-language-profiles.py "$(TARGET_DIR)" "$(OUTPUT_DIR)"

supply-chain-sbom: toolbox-check ## Generate a CycloneDX JSON SBOM with Syft
	@rm -f "$(SBOM_REPORT)"
	@syft scan "dir:$(TARGET_DIR)" \
		--quiet \
		--output "cyclonedx-json=$(SBOM_REPORT)"

# Maintenance targets are explicitly disabled from MCP exposure in .makefile-mcp.yaml.
toolbox-check:
	@test -d "$(TARGET_DIR)" || { echo "missing $(TARGET_DIR)/; mount the audited repository there" >&2; exit 2; }
	@mkdir -p "$(OUTPUT_DIR)"

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

test:
	@./tests/smoke.sh

image:
	@docker build -t appsec-toolbox-mcp:dev .
