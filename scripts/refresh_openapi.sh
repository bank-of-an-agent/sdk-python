#!/usr/bin/env bash
# Refresh openapi.json from the TypeScript monorepo and regenerate the models.
#
#   scripts/refresh_openapi.sh                 # uses ../agent-bank
#   AGENT_BANK_DIR=/path/to/agent-bank scripts/refresh_openapi.sh
#
# The monorepo generates docs/openapi.json from its route registry
# (`pnpm openapi`); run that first if the route registry changed.
set -euo pipefail

cd "$(dirname "$0")/.."
source_dir="${AGENT_BANK_DIR:-../agent-bank}"
source_file="$source_dir/docs/openapi.json"

if [[ ! -f "$source_file" ]]; then
  echo "error: $source_file not found (set AGENT_BANK_DIR)" >&2
  exit 1
fi

cp "$source_file" openapi.json
echo "Copied $source_file -> openapi.json"
scripts/generate_models.sh
git --no-pager diff --stat -- openapi.json src/agentbank/models.py src/agentbank/_operations.py || true
