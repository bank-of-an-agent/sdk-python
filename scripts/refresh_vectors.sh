#!/usr/bin/env bash
# Refresh tests/vectors.json (cross-language signing vectors) from the TypeScript monorepo.
#
#   scripts/refresh_vectors.sh
#   AGENT_BANK_DIR=/path/to/agent-bank scripts/refresh_vectors.sh
set -euo pipefail

cd "$(dirname "$0")/.."
source_dir="${AGENT_BANK_DIR:-../agent-bank}"
source_file="$source_dir/packages/core/test/vectors/vectors.json"

if [[ ! -f "$source_file" ]]; then
  echo "error: $source_file not found (set AGENT_BANK_DIR)" >&2
  exit 1
fi

cp "$source_file" tests/vectors.json
echo "Copied $source_file -> tests/vectors.json"
git --no-pager diff --stat -- tests/vectors.json || true
