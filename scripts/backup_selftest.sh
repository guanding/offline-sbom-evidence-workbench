#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <verified-selftest-output-root> <new-backup-directory>" >&2
  exit 64
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$project_root"

exec uv run --offline sbom-workbench backup-selftest \
  --source-root "$1" \
  --backup "$2"
