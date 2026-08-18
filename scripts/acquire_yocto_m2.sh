#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
inputs_root=${1:-"$project_root/runtime/yocto-public-references"}
profiles="$project_root/datasets/yocto_reference_profiles.json"

mkdir -p "$inputs_root"

for profile_id in \
  yocto-6.0-core-image-minimal-qemuarm64 \
  yocto-6.0.2-core-image-minimal-qemuarm64
do
  uv run --project "$project_root" sbom-workbench acquire-yocto-reference \
    --profiles "$profiles" \
    --profile-id "$profile_id" \
    --destination "$inputs_root/$profile_id"
done
