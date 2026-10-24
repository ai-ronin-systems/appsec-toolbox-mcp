SHELL := /bin/sh
.SHELLFLAGS := -eu -c

TARGET_DIR := target
OUTPUT_DIR := output
APPSEC_LANGS ?= auto

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
$(if $(filter $@,$(MAKECMDGOALS)),@./scripts/write-manifest.py "$(TARGET_DIR)" "$(OUTPUT_DIR)" "$@")
endef

.PHONY: appsec-full security-semgrep security-gitleaks security-osv security-trivy security-checkov security-language \
        supply-chain-sbom toolbox-check toolbox-versions test test-image image

appsec-full: security-semgrep security-gitleaks security-osv security-trivy security-checkov security-language supply-chain-sbom ## Run the complete passive AppSec evidence bundle
	$(manifest)

security-semgrep: toolbox-check ## Run Semgrep SAST and inventory suppression markers in the mounted target
	@rm -f "$(SEMGREP_REPORT)" "$(SUPPRESSIONS_REPORT)"
	@./scripts/find-suppressions.py "$(TARGET_DIR)" "$(OUTPUT_DIR)"
	@semgrep scan \
		--config p/default \
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
	@./scripts/run-osv.sh "$(TARGET_DIR)" "$(OSV_REPORT)"
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
		> "$(CHECKOV_REPORT)"
	$(manifest)

security-language: toolbox-check ## Run applicable language-specific passive SAST profiles
	@rm -f "$(LANGUAGE_PROFILE_REPORT)"
	@APPSEC_LANGS="$(APPSEC_LANGS)" ./scripts/run-language-profiles.py "$(TARGET_DIR)" "$(OUTPUT_DIR)"
	$(manifest)

supply-chain-sbom: toolbox-check ## Generate a CycloneDX JSON SBOM with Syft
	@rm -f "$(SBOM_REPORT)"
	@syft scan "dir:$(TARGET_DIR)" \
		--quiet \
		--output "cyclonedx-json=$(SBOM_REPORT)"
	$(manifest)

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

# Known-positive run of the real image against examples/vulnerable-sample (Docker + network).
test-image:
	@./tests/image.sh

image:
	@docker build -t appsec-toolbox-mcp:dev .
