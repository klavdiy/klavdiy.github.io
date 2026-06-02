#!/usr/bin/env bash
# Generates static/admin/config.yml for build (values from env, not committed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/static/admin/config.yml"
EXAMPLE="$ROOT/static/admin/config.yml.example"

: "${DECAP_OAUTH_BASE_URL:?Set DECAP_OAUTH_BASE_URL}"
: "${DECAP_GITHUB_REPO:?Set DECAP_GITHUB_REPO}"

if [[ ! -f "$EXAMPLE" ]]; then
  echo "Missing $EXAMPLE" >&2
  exit 1
fi

cp "$EXAMPLE" "$OUT"
if [[ "$(uname)" == "Darwin" ]]; then
  sed -i '' "s|YOUR_GITHUB_USER/YOUR_REPO|${DECAP_GITHUB_REPO}|g" "$OUT"
  sed -i '' "s|https://YOUR-OAUTH-WORKER.workers.dev|${DECAP_OAUTH_BASE_URL}|g" "$OUT"
else
  sed -i "s|YOUR_GITHUB_USER/YOUR_REPO|${DECAP_GITHUB_REPO}|g" "$OUT"
  sed -i "s|https://YOUR-OAUTH-WORKER.workers.dev|${DECAP_OAUTH_BASE_URL}|g" "$OUT"
fi

echo "Generated $OUT (not for commit)"
