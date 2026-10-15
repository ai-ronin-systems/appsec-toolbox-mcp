FROM python:3.12-slim-bookworm

ARG MAKEFILE_MCP_SPEC="makefile-mcp==0.2.2"
ARG SEMGREP_VERSION="1.174.0"
ARG GITLEAKS_VERSION="8.29.1"
ARG OSV_SCANNER_VERSION="2.5.1"
ARG TRIVY_VERSION="0.74.0"
ARG CHECKOV_VERSION="3.3.8"
ARG BANDIT_VERSION="1.9.4"
ARG NJSSCAN_VERSION="0.4.3"
ARG GOSEC_VERSION="2.28.0"
ARG GO_VERSION="1.27.0"
ARG FINDSECBUGS_VERSION="1.14.0"
ARG SYFT_VERSION="1.51.0"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl make tar unzip openjdk-17-jre-headless \
 && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir "${MAKEFILE_MCP_SPEC}"

# Isolate every Python scanner's dependency graph from the Makefile MCP runtime. Semgrep pins
# its own MCP SDK (mcp 1.x), which cannot share an environment with Makefile MCP (mcp 2.x).
RUN python -m venv /opt/semgrep \
 && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
 && python -m venv /opt/checkov \
 && /opt/checkov/bin/pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" \
 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
 && python -m venv /opt/bandit \
 && /opt/bandit/bin/pip install --no-cache-dir "bandit==${BANDIT_VERSION}" \
 && ln -s /opt/bandit/bin/bandit /usr/local/bin/bandit \
 && python -m venv /opt/njsscan \
 && /opt/njsscan/bin/pip install --no-cache-dir "njsscan==${NJSSCAN_VERSION}" \
 && ln -s /opt/njsscan/bin/njsscan /usr/local/bin/njsscan

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) \
        gl_arch=x64; osv_arch=amd64; trivy_arch=64bit; syft_arch=amd64; gosec_arch=amd64; go_arch=amd64; \
        go_sha=675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685; \
        gosec_sha=d7882e505b1ff345d458bf0e893eec8019bc849f861ad73a212869540dd505ff ;; \
      arm64) \
        gl_arch=arm64; osv_arch=arm64; trivy_arch=ARM64; syft_arch=arm64; gosec_arch=arm64; go_arch=arm64; \
        go_sha=51798d2c42d0e1c6ed7fd9f48728b4193abac9e8aad6dbac2fe96a81f5909bda; \
        gosec_sha=63259681b6e4b9e7a24d4e187b485e75d3844d28d512b0c97dc831e51d374720 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_arch}" \
      -o /usr/local/bin/osv-scanner; \
    chmod 0755 /usr/local/bin/osv-scanner; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin trivy; \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${syft_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin syft; \
    curl -fsSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${gosec_arch}.tar.gz" \
      -o /tmp/gosec.tar.gz; \
    echo "${gosec_sha}  /tmp/gosec.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gosec.tar.gz -C /usr/local/bin gosec; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" -o /tmp/go.tar.gz; \
    echo "${go_sha}  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/go.tar.gz -C /usr/local; \
    curl -fsSL "https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-${FINDSECBUGS_VERSION}/findsecbugs-cli-${FINDSECBUGS_VERSION}.zip" \
      -o /tmp/findsecbugs.zip; \
    mkdir -p /opt/findsecbugs; \
    unzip -q /tmp/findsecbugs.zip -d /opt/findsecbugs; \
    fsb="$(find /opt/findsecbugs -type f -name findsecbugs.sh -print -quit)"; \
    test -n "$fsb"; \
    sed -i 's/\r$//' "$fsb"; \
    chmod 0755 "$fsb"; \
    ln -s "$fsb" /usr/local/bin/findsecbugs; \
    rm -f /tmp/gosec.tar.gz /tmp/go.tar.gz /tmp/findsecbugs.zip

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin toolbox

WORKDIR /runner
COPY --chown=toolbox:toolbox Makefile .makefile-mcp.yaml ./
COPY --chown=toolbox:toolbox scripts/ ./scripts/
COPY --chown=toolbox:toolbox config/ ./config/
# Makefile MCP keeps its task locks under /runner/.makefile-mcp. The root filesystem is
# read-only at runtime, so that state lives on the /tmp tmpfs; the entrypoint creates it.
RUN mkdir -p target output \
 && ln -s /tmp/makefile-mcp /runner/.makefile-mcp \
 && chown -R toolbox:toolbox /runner

USER toolbox
ENV HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/cache \
    PYTHONUNBUFFERED=1 \
    PATH=/usr/local/go/bin:${PATH} \
    APPSEC_LANGS=auto

ENTRYPOINT ["./scripts/entrypoint.sh"]
CMD ["makefile-mcp", "serve"]

# Pinned tool versions for run-manifest.json, written last so a version bump does not
# invalidate the scanner layers. VERSION is the single source of the toolbox version.
COPY --chown=toolbox:toolbox VERSION ./
RUN printf '{"appsec-toolbox-mcp":"%s","makefile-mcp":"%s","semgrep":"%s","gitleaks":"%s","osv-scanner":"%s","trivy":"%s","checkov":"%s","bandit":"%s","njsscan":"%s","gosec":"%s","findsecbugs":"%s","syft":"%s","go":"%s"}\n' \
      "$(cat VERSION)" "$(makefile-mcp --version)" "$SEMGREP_VERSION" "$GITLEAKS_VERSION" "$OSV_SCANNER_VERSION" \
      "$TRIVY_VERSION" "$CHECKOV_VERSION" "$BANDIT_VERSION" "$NJSSCAN_VERSION" "$GOSEC_VERSION" \
      "$FINDSECBUGS_VERSION" "$SYFT_VERSION" "$GO_VERSION" > tool-versions.json \
 && python3 -m json.tool tool-versions.json >/dev/null

# The source label links the GHCR package to this repository.
LABEL org.opencontainers.image.title="appsec-toolbox-mcp" \
      org.opencontainers.image.description="Passive AppSec scanners exposed to AI agents as governed MCP tools via Makefile MCP." \
      org.opencontainers.image.source="https://github.com/ai-ronin-systems/appsec-toolbox-mcp" \
      org.opencontainers.image.licenses="Apache-2.0"
