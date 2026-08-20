#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/sbom-workbench-public-tests.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

cd "$project_root"

if [ -f "$project_root/PUBLIC_RELEASE_MANIFEST.sha256" ]; then
  python3 release/verify_public_candidate.py "$project_root"
fi

UV_PROJECT_ENVIRONMENT="$test_root/venv" \
PYTHONDONTWRITEBYTECODE=1 \
  uv sync --frozen --offline --no-install-project

PYTHONPATH="$project_root/src:$project_root" \
SBOM_WORKBENCH_REQUIRE_LOOPBACK_TESTS=1 \
PYTHONDONTWRITEBYTECODE=1 \
  "$test_root/venv/bin/python" -B release/run_public_tests.py

if [ -f "$project_root/PUBLIC_RELEASE_MANIFEST.sha256" ]; then
  python3 release/verify_public_candidate.py "$project_root"
fi
