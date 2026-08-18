#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
demo_root=${1:-"$project_root/runtime/demo-data"}
demo_port=${2:-8765}

if [ ! -f "$demo_root/runs.json" ]; then
  echo "BLOCKED: no registered demo runs; run scripts/build_demo.sh first." >&2
  exit 2
fi

cd "$project_root"
PYTHONDONTWRITEBYTECODE=1 uv run --offline sbom-workbench serve \
  --data-root "$demo_root" \
  --port "$demo_port"

