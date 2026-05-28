#!/usr/bin/env bash
set -euo pipefail

base_ref="${TRUFFLEHOG_BASE_REF:-origin/next}"
head_ref="${TRUFFLEHOG_HEAD_REF:-HEAD}"

if ! git rev-parse --verify --quiet "${base_ref}" >/dev/null; then
  git fetch origin next:refs/remotes/origin/next
fi

base_sha="$(git merge-base "${base_ref}" "${head_ref}")"
head_sha="$(git rev-parse "${head_ref}")"
repo_url="file://."
tmpdir=""

if [[ ! -d .git ]]; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT
  git clone --shared "$(git rev-parse --show-toplevel)" "${tmpdir}/repo" >/dev/null 2>&1
  repo_url="file://${tmpdir}/repo"
fi

env -u PRE_COMMIT trufflehog git "${repo_url}" \
  --since-commit "${base_sha}" \
  --branch "${head_sha}" \
  --results=verified,unknown \
  --fail \
  --fail-on-scan-errors \
  --no-update
