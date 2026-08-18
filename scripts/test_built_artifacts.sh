#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
artifact_root=$(mktemp -d "${TMPDIR:-/tmp}/sbom-workbench-artifacts.XXXXXX")
trap 'rm -rf "$artifact_root"' EXIT HUP INT TERM

SOURCE_DATE_EPOCH=315532800 \
  uv build --offline --out-dir "$artifact_root/dist" "$project_root"

wheel=$(find "$artifact_root/dist" -maxdepth 1 -type f -name '*.whl' -print)
sdist=$(find "$artifact_root/dist" -maxdepth 1 -type f -name '*.tar.gz' -print)
if [ -z "$wheel" ] || [ -z "$sdist" ]; then
  printf '%s\n' "wheel or sdist was not produced" >&2
  exit 2
fi

SOURCE_DATE_EPOCH=315532800 \
  "$project_root/.venv/bin/python" -B "$project_root/scripts/normalize_sdist.py" "$sdist"

SBOM_WORKBENCH_BUILT_WHEEL=$wheel \
SBOM_WORKBENCH_BUILT_SDIST=$sdist \
PYTHONDONTWRITEBYTECODE=1 \
  "$project_root/.venv/bin/python" -B -m unittest discover \
    -s "$project_root/tests" -p 'test_built_artifacts.py' -v
