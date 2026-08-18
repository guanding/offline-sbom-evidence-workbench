#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
demo_root=${1:-"$project_root/runtime/demo-data"}

if [ -e "$demo_root/runs.json" ]; then
  echo "BLOCKED: demo data already exists; choose a new empty directory." >&2
  exit 2
fi

cd "$project_root"
PYTHONDONTWRITEBYTECODE=1 uv sync --frozen --offline
PYTHONDONTWRITEBYTECODE=1 uv run --offline sbom-workbench demo \
  --fixtures-root "$project_root/fixtures/synthetic_orion" \
  --data-root "$demo_root"

