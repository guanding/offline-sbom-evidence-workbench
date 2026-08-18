#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <backup-directory> <new-restore-directory> <trusted-manifest-sha256>" >&2
  exit 64
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$project_root"

exec uv run --offline sbom-workbench restore-selftest \
  --backup "$1" \
  --destination "$2" \
  --trusted-manifest-sha256 "$3"
