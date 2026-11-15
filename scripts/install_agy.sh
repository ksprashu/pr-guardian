#!/usr/bin/env bash
# Install the pinned Antigravity CLI (agy) on an ubuntu-latest (linux/amd64) runner.
# The archive is checked against the SHA-512 its release manifest published.
# Bump version, URL and checksum together (scripts/check_pins.py --online reports drift).
set -euo pipefail

AGY_VERSION=1.5.9
AGY_URL="https://storage.googleapis.com/antigravity-public/antigravity-cli/1.5.9-4515810895593472/linux-x64/cli_linux_x64.tar.gz"
AGY_SHA512=d01eb13ba7750eed18907f1ae8860864371e0ad9064415e8d033d22b4bd7b9b4e4c7f962058520b452d67db1c33163d9a889d55a7dffa159596ec6cd91a87b79
AGY_MANIFEST="https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/linux_amd64.json"
AGY_PREFIX="https://storage.googleapis.com/antigravity-public/antigravity-cli/"

BIN="$HOME/.local/bin"
mkdir -p "$BIN"
cd "$(mktemp -d)"

if curl -fsSL --retry 3 -o agy.tgz "$AGY_URL"; then
  echo "$AGY_SHA512  agy.tgz" | sha512sum -c --quiet -
else
  # The pinned build is no longer served. Install the current release instead, still
  # checked against its manifest hash, and say so: a hard pin here would stop every
  # review in every governed repo until someone re-pins.
  echo "::warning::agy $AGY_VERSION is no longer downloadable; installing the current release. Re-pin scripts/install_agy.sh."
  manifest="$(curl -fsSL --retry 3 "$AGY_MANIFEST")"
  url="$(jq -er .url <<<"$manifest")"
  sha="$(jq -er .sha512 <<<"$manifest")"
  case "$url" in
    "$AGY_PREFIX"*) ;;
    *) echo "::error::agy manifest points outside $AGY_PREFIX"; exit 1 ;;
  esac
  [[ "$sha" =~ ^[0-9a-f]{128}$ ]] || { echo "::error::agy manifest has no SHA-512"; exit 1; }
  curl -fsSL --retry 3 -o agy.tgz "$url"
  echo "$sha  agy.tgz" | sha512sum -c --quiet -
fi

tar -xzf agy.tgz antigravity
install -m 0755 antigravity "$BIN/agy"
echo "$BIN" >> "${GITHUB_PATH:-/dev/null}"
"$BIN/agy" --version || true
