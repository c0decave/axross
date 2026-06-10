FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Update and install base tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    git \
    jq \
    curl \
    unzip \
    openjdk-21-jre-headless \
    zaproxy \
    nmap \
    nikto \
    ffuf \
    seclists \
    wordlists \
    yara \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment for Python tools
RUN python3 -m venv /opt/tools

# Install Python security & analysis tools
RUN /opt/tools/bin/pip install --no-cache-dir \
    bandit \
    semgrep \
    safety \
    pip-audit \
    python-owasp-zap-v2.4 \
    pyyaml \
    markdown \
    weasyprint \
    pylint \
    flake8 \
    dodgy \
    njsscan

# Install Node.js security tools
RUN npm install -g \
    eslint \
    retire

# Install gitleaks
RUN set -e; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in amd64) GL_ARCH=x64 ;; arm64) GL_ARCH=arm64 ;; *) GL_ARCH=x64 ;; esac; \
    curl -fSL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GL_ARCH}.tar.gz" -o /tmp/gl.tar.gz; \
    tar -xzf /tmp/gl.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/gl.tar.gz

# Install hadolint
RUN set -e; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in amd64) HL_ARCH=x86_64 ;; arm64) HL_ARCH=arm64 ;; *) HL_ARCH=x86_64 ;; esac; \
    curl -fSL "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-${HL_ARCH}" -o /usr/local/bin/hadolint; \
    chmod +x /usr/local/bin/hadolint

# Install katana
RUN set -e; \
    KATANA_TAG=$(curl -sSL https://api.github.com/repos/projectdiscovery/katana/releases/latest | jq -r .tag_name); \
    if [ -z "$KATANA_TAG" ] || [ "$KATANA_TAG" = "null" ]; then echo "Failed to resolve katana tag"; exit 1; fi; \
    KATANA_VER=${KATANA_TAG#v}; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in amd64) KATANA_ARCH=amd64 ;; arm64) KATANA_ARCH=arm64 ;; *) KATANA_ARCH=amd64 ;; esac; \
    curl -fSL "https://github.com/projectdiscovery/katana/releases/download/${KATANA_TAG}/katana_${KATANA_VER}_linux_${KATANA_ARCH}.zip" -o /tmp/katana.zip; \
    mkdir -p /tmp/katana; \
    unzip -q /tmp/katana.zip -d /tmp/katana; \
    KATANA_BIN=$(find /tmp/katana -type f -name katana -maxdepth 3 | head -n 1); \
    if [ -z "$KATANA_BIN" ]; then echo "Katana binary not found in archive"; exit 1; fi; \
    install -m 0755 "$KATANA_BIN" /usr/local/bin/katana; \
    rm -rf /tmp/katana /tmp/katana.zip

# Install trufflehog
RUN set -e; \
    TH_TAG=$(curl -sSL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r .tag_name); \
    if [ -z "$TH_TAG" ] || [ "$TH_TAG" = "null" ]; then echo "Failed to resolve trufflehog tag"; exit 1; fi; \
    TH_VER=${TH_TAG#v}; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in amd64) TH_ARCH=amd64 ;; arm64) TH_ARCH=arm64 ;; *) TH_ARCH=amd64 ;; esac; \
    curl -fSL "https://github.com/trufflesecurity/trufflehog/releases/download/${TH_TAG}/trufflehog_${TH_VER}_linux_${TH_ARCH}.tar.gz" -o /tmp/trufflehog.tar.gz; \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog; \
    rm /tmp/trufflehog.tar.gz

# Install osv-scanner
RUN set -e; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in amd64) OSV_ARCH=amd64 ;; arm64) OSV_ARCH=arm64 ;; *) OSV_ARCH=amd64 ;; esac; \
    curl -fSL "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${OSV_ARCH}" -o /usr/local/bin/osv-scanner; \
    chmod +x /usr/local/bin/osv-scanner

# Install ZAP baseline script helpers
RUN curl -fSL https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap-baseline.py -o /usr/local/bin/zap-baseline.py && \
    curl -fSL https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap_common.py -o /usr/local/bin/zap_common.py && \
    chmod +x /usr/local/bin/zap-baseline.py

# Provide expected ZAP paths for baseline script
RUN mkdir -p /zap/wrk && \
    printf '%s\n' '#!/bin/sh' 'exec /usr/bin/zaproxy "$@"' > /zap/zap-x.sh && \
    chmod +x /zap/zap-x.sh

# Install syft + grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh -o /tmp/syft-install.sh && \
    sh /tmp/syft-install.sh -b /usr/local/bin && \
    rm /tmp/syft-install.sh

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh -o /tmp/grype-install.sh && \
    sh /tmp/grype-install.sh -b /usr/local/bin && \
    rm /tmp/grype-install.sh

# Add tools venv to PATH
ENV PATH="/opt/tools/bin:${PATH}"

WORKDIR /src

COPY run_analysis.sh /opt/run_analysis.sh
COPY scan_natural_language.py /opt/scan_natural_language.py
COPY scan_network_egress.py /opt/scan_network_egress.py
COPY entropy_scan.py /opt/entropy_scan.py
COPY sbom_diff.py /opt/sbom_diff.py
COPY generate_report.py /opt/generate_report.py
COPY semgrep/backdoor_rules.yml /opt/semgrep/backdoor_rules.yml
COPY yara_rules/backdoor_rules.yar /opt/yara_rules/backdoor_rules.yar
RUN chmod +x /opt/run_analysis.sh

# Drop root privileges. The container reads /src (mounted read-only
# in the typical invocation) and writes reports under /reports;
# anything else would be a sign the analyzer is doing too much.
# UID 1000 to match a typical desktop host so volume mounts with
# host UID 1000 don't trip permission checks.
RUN useradd --create-home --uid 1000 --shell /bin/bash analyzer \
    && mkdir -p /reports \
    && chown analyzer:analyzer /reports /src 2>/dev/null || true
USER analyzer

ENTRYPOINT ["/opt/run_analysis.sh"]
