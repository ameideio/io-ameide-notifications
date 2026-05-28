#!/usr/bin/env bash
set -euo pipefail

base_ref="${LOCAL_PREPUSH_BASE_REF:-origin/next}"
head_ref="${LOCAL_PREPUSH_HEAD_REF:-HEAD}"

git fetch origin next --prune

corepack prepare pnpm@10.33.0 --activate
pnpm install --frozen-lockfile

.github/workflows/scripts/stop-only.sh .
pnpm nx affected -t lint,build,test --base="${base_ref}" --head="${head_ref}" --parallel=4

if [[ -x .github/workflows/scripts/validate-submodule-sync.sh ]]; then
  .github/workflows/scripts/validate-submodule-sync.sh next || {
    echo "submodule sync validation could not complete locally; CI remains authoritative."
  }
fi

if command -v trufflehog >/dev/null 2>&1; then
  bash tools/precommit/trufflehog-range.sh
else
  echo "trufflehog not found; skipping local secret scan. CI remains authoritative."
fi
