#!/usr/bin/env bash
# Regenerate src/agentbank/models.py (Pydantic v2) and src/agentbank/_operations.py
# from openapi.json. Commit both generated files.
#
#   scripts/generate_models.sh          # regenerate in place
#   scripts/generate_models.sh --check  # fail if the committed files are stale (CI)
set -euo pipefail

cd "$(dirname "$0")/.."
# A PYTHONPATH inherited from the host (e.g. a Nix Python environment) would leak
# foreign site-packages into the uv-managed environment.
unset PYTHONPATH

check=0
if [[ "${1:-}" == "--check" ]]; then
  check=1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

uv run --group codegen python scripts/prepare_codegen_schema.py openapi.json "$tmp/openapi.codegen.json"

uv run --group codegen datamodel-codegen \
  --input "$tmp/openapi.codegen.json" \
  --input-file-type openapi \
  --openapi-scopes schemas \
  --output "$tmp/models.raw.py" \
  --output-model-type pydantic_v2.BaseModel \
  --base-class agentbank._models_base.AgentBankModel \
  --target-python-version 3.10 \
  --use-standard-collections \
  --use-union-operator \
  --use-annotated \
  --field-constraints \
  --enum-field-as-literal all \
  --use-double-quotes \
  --use-schema-description \
  --use-field-description \
  --disable-timestamp \
  --strict-nullable \
  --collapse-root-models \
  --use-type-alias \
  --use-title-as-name \
  --reuse-model \
  --output-datetime-class AwareDatetime \
  --formatters builtin

uv run --group codegen python scripts/postprocess_models.py "$tmp/models.raw.py" "$tmp/models.py"
uv run --group codegen python scripts/generate_operations.py openapi.json "$tmp/_operations.py"
uv run ruff format --quiet --config pyproject.toml "$tmp/models.py" "$tmp/_operations.py"
uv run ruff check --quiet --fix --config pyproject.toml --select I,F401 "$tmp/_operations.py"

if [[ "$check" == "1" ]]; then
  status=0
  for file in models.py _operations.py; do
    if ! diff -u "src/agentbank/$file" "$tmp/$file"; then
      echo "src/agentbank/$file is stale: run scripts/generate_models.sh" >&2
      status=1
    fi
  done
  exit "$status"
fi

cp "$tmp/models.py" src/agentbank/models.py
cp "$tmp/_operations.py" src/agentbank/_operations.py
echo "Generated src/agentbank/models.py and src/agentbank/_operations.py"
