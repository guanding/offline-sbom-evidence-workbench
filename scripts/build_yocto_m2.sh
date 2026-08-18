#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
inputs_root=${1:-"$project_root/runtime/yocto-public-references"}
data_root=${2:-"$project_root/runtime/demo-data"}
profiles="$project_root/datasets/yocto_reference_profiles.json"

uv run --project "$project_root" --offline sbom-workbench yocto-reference-demo \
  --profiles "$profiles" \
  --inputs-root "$inputs_root" \
  --data-root "$data_root"
