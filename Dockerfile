# Pinned by digest so a rebuild cannot pick up a different base; Dependabot proposes updates.
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

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
# FindSecBugs ships one architecture-independent archive.
ARG FINDSECBUGS_SHA256="ff546e16e596ade5b6534a6da87881e569429bf46dfd8faed63ca63cdd69b4f8"
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

# Every download is checked against the SHA-256 its project publishes before it is used.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) \
        gl_arch=x64; osv_arch=amd64; trivy_arch=64bit; syft_arch=amd64; gosec_arch=amd64; go_arch=amd64; \
        gitleaks_sha=e4eb209d04e20339d77122a3bdf9cd41351255cfb27ebcb75e85325e04f88924; \
        osv_sha=f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be; \
        trivy_sha=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a; \
        syft_sha=2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f; \
        go_sha=675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685; \
        gosec_sha=d7882e505b1ff345d458bf0e893eec8019bc849f861ad73a212869540dd505ff ;; \
      arm64) \
        gl_arch=arm64; osv_arch=arm64; trivy_arch=ARM64; syft_arch=arm64; gosec_arch=arm64; go_arch=arm64; \
        gitleaks_sha=691f826ce7c1c564c9c02d0f9025e8e70803e3816707a4be6224408a06a81eaa; \
        osv_sha=3d0f5aa5a6baa8eb32bcef247388e149ef6030a6634ccae6fa0d62681fb27a6d; \
        trivy_sha=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5; \
        syft_sha=6c0466811541ea03add5213a60a1562f0851e4c0b0ecfdee1a694a9455285900; \
        go_sha=51798d2c42d0e1c6ed7fd9f48728b4193abac9e8aad6dbac2fe96a81f5909bda; \
        gosec_sha=63259681b6e4b9e7a24d4e187b485e75d3844d28d512b0c97dc831e51d374720 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    fetch() { curl -fsSL "$1" -o "$2"; echo "$3  $2" | sha256sum -c -; }; \
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
      /tmp/gitleaks.tar.gz "$gitleaks_sha"; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    fetch "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_arch}" \
      /usr/local/bin/osv-scanner "$osv_sha"; \
    chmod 0755 /usr/local/bin/osv-scanner; \
    fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" \
      /tmp/trivy.tar.gz "$trivy_sha"; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    fetch "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${syft_arch}.tar.gz" \
      /tmp/syft.tar.gz "$syft_sha"; \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft; \
    fetch "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${gosec_arch}.tar.gz" \
      /tmp/gosec.tar.gz "$gosec_sha"; \
    tar -xzf /tmp/gosec.tar.gz -C /usr/local/bin gosec; \
    fetch "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" /tmp/go.tar.gz "$go_sha"; \
    tar -xzf /tmp/go.tar.gz -C /usr/local; \
    fetch "https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-${FINDSECBUGS_VERSION}/findsecbugs-cli-${FINDSECBUGS_VERSION}.zip" \
      /tmp/findsecbugs.zip "$FINDSECBUGS_SHA256"; \
    mkdir -p /opt/findsecbugs; \
    unzip -q /tmp/findsecbugs.zip -d /opt/findsecbugs; \
    fsb="$(find /opt/findsecbugs -type f -name findsecbugs.sh -print -quit)"; \
    test -n "$fsb"; \
    sed -i 's/\r$//' "$fsb"; \
    chmod 0755 "$fsb"; \
    ln -s "$fsb" /usr/local/bin/findsecbugs; \
    rm -f /tmp/gitleaks.tar.gz /tmp/trivy.tar.gz /tmp/syft.tar.gz /tmp/gosec.tar.gz /tmp/go.tar.gz /tmp/findsecbugs.zip

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
