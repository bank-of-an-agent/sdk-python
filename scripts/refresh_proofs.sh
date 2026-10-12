#!/usr/bin/env bash
# Refresh the private-proofs files copied from the TypeScript monorepo:
#
#   * src/agentbank/proofs_data/{manifest.json,verification_key.json}, the claims circuit's
#     manifest and Groth16 verification key (from packages/proofs/artifacts), copied byte for
#     byte and only if the key matches the SHA-256 in the manifest;
#   * tests/proof_vectors.json, the cross-language vectors (packages/proofs/test/vectors).
#
#   scripts/refresh_proofs.sh
#   AGENT_BANK_DIR=/path/to/agent-bank scripts/refresh_proofs.sh
set -euo pipefail

cd "$(dirname "$0")/.."
source_dir="${AGENT_BANK_DIR:-../agent-bank}/packages/proofs"
artifacts="$source_dir/artifacts"
vectors="$source_dir/test/vectors/proofs.json"

for file in "$artifacts/manifest.json" "$artifacts/verification_key.json" "$vectors"; do
  if [[ ! -f "$file" ]]; then
    echo "error: $file not found (set AGENT_BANK_DIR)" >&2
    exit 1
  fi
done

expected="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["sha256"]["verification_key"])' "$artifacts/manifest.json")"
actual="$(sha256sum "$artifacts/verification_key.json" | cut -d' ' -f1)"
if [[ "$expected" != "$actual" ]]; then
  echo "error: verification_key.json does not match the manifest ($actual != $expected)" >&2
  exit 1
fi

mkdir -p src/agentbank/proofs_data
cp "$artifacts/manifest.json" "$artifacts/verification_key.json" src/agentbank/proofs_data/
cp "$vectors" tests/proof_vectors.json
echo "Copied the circuit manifest and verification key -> src/agentbank/proofs_data/"
echo "Copied $vectors -> tests/proof_vectors.json"
git --no-pager diff --stat -- src/agentbank/proofs_data tests/proof_vectors.json || true
