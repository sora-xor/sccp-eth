#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Prefer local Node 22 on macOS Homebrew installs when the current shell uses a non-LTS Node.
node22_bin="$("${script_dir}/select_node22_path.sh")"

if [[ -n "${node22_bin}" && -x "${node22_bin}/npx" ]] && "${node22_bin}/npx" --no-install hardhat --version >/dev/null 2>&1; then
  exec "${node22_bin}/npx" --no-install hardhat "$@"
fi

if command -v npx >/dev/null 2>&1 && npx --no-install hardhat --version >/dev/null 2>&1; then
  exec npx --no-install hardhat "$@"
fi

if command -v hardhat >/dev/null 2>&1; then
  exec hardhat "$@"
fi

echo "hardhat CLI not found (tried npx and PATH)" >&2
exit 1
