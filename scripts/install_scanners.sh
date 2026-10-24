#!/usr/bin/env bash
# Install the pinned scanner set on an ubuntu-latest (linux/amd64) runner.
# Every binary is checked against the SHA-256 from its upstream release.
# Bump a version by updating its line and checksum together.
set -euo pipefail

BIN="${RUNNER_TEMP:-/tmp}/prg-bin"
mkdir -p "$BIN"
cd "$(mktemp -d)"

fetch() { # url sha256 out
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet -
}

GITLEAKS=8.30.1;   GITLEAKS_SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
OSV=2.7.0;         OSV_SHA=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ACTIONLINT=1.7.12; ACTIONLINT_SHA=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
TRIVY=0.76.1;      TRIVY_SHA=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
SEMGREP=1.182.1; ZIZMOR=1.31.1; PIP_AUDIT=2.10.1

fetch "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS/gitleaks_${GITLEAKS}_linux_x64.tar.gz" "$GITLEAKS_SHA" gitleaks.tgz
tar -xzf gitleaks.tgz gitleaks && mv gitleaks "$BIN/"

fetch "https://github.com/google/osv-scanner/releases/download/v$OSV/osv-scanner_linux_amd64" "$OSV_SHA" osv-scanner
chmod +x osv-scanner && mv osv-scanner "$BIN/"

fetch "https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT/actionlint_${ACTIONLINT}_linux_amd64.tar.gz" "$ACTIONLINT_SHA" actionlint.tgz
tar -xzf actionlint.tgz actionlint && mv actionlint "$BIN/"

fetch "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY/trivy_${TRIVY}_Linux-64bit.tar.gz" "$TRIVY_SHA" trivy.tgz
tar -xzf trivy.tgz trivy && mv trivy "$BIN/"

python3 -m pip install --quiet --user "semgrep==$SEMGREP" "zizmor==$ZIZMOR" "pip-audit==$PIP_AUDIT"

echo "$BIN" >> "${GITHUB_PATH:-/dev/null}"
echo "$HOME/.local/bin" >> "${GITHUB_PATH:-/dev/null}"
"$BIN/gitleaks" version && "$BIN/osv-scanner" --version | head -1 && "$BIN/actionlint" --version | head -1 && "$BIN/trivy" --version | head -1
