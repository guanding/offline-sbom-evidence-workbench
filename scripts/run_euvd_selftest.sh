#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -z "${SBOM_WORKBENCH_EUVD_SOURCE_ROOT:-}" ]; then
  printf '%s\n' \
    "SBOM_WORKBENCH_EUVD_SOURCE_ROOT must name the absolute live EUVD source tree" >&2
  exit 2
fi
active_source_root=$SBOM_WORKBENCH_EUVD_SOURCE_ROOT
case "$active_source_root" in
  /*) ;;
  *)
    printf '%s\n' "SBOM_WORKBENCH_EUVD_SOURCE_ROOT must be absolute" >&2
    exit 2
    ;;
esac

if [ "$#" -ne 6 ]; then
  printf '%s\n' \
    "usage: $0 SOURCE_SNAPSHOT IMAGE_ARCHIVE PORTABLE_SNAPSHOT SYFT_BIN SYFT_CONFIG OUTPUT_ROOT" \
    "all six paths are required; SOURCE_SNAPSHOT must be an isolated, stable copy" >&2
  exit 2
fi

source_root=$1
image_archive=$2
portable_root=$3
syft_bin=$4
syft_config=$5
output_root=$6

for directory in "$source_root" "$portable_root"; do
  if [ ! -d "$directory" ] || [ -L "$directory" ]; then
    printf '%s\n' "required input is not a non-symlink directory: $directory" >&2
    exit 2
  fi
done
for regular_file in "$image_archive" "$syft_config"; do
  if [ ! -f "$regular_file" ] || [ -L "$regular_file" ]; then
    printf '%s\n' "required input is not a non-symlink regular file: $regular_file" >&2
    exit 2
  fi
done
if [ ! -f "$syft_bin" ] || [ -L "$syft_bin" ] || [ ! -x "$syft_bin" ]; then
  printf '%s\n' "Syft path is not an executable non-symlink file: $syft_bin" >&2
  exit 2
fi
if [ -e "$output_root" ] || [ -L "$output_root" ]; then
  printf '%s\n' "refusing to overwrite output path: $output_root" >&2
  exit 2
fi

canonical_source=$(CDPATH= cd -- "$source_root" && pwd -P)
if [ "$canonical_source" = "$active_source_root" ]; then
  printf '%s\n' \
    "refusing active source directory; create and pass an isolated exact-set snapshot" >&2
  exit 2
fi

case "$output_root/" in
  "$canonical_source"/*)
    printf '%s\n' "output must not be inside the source snapshot" >&2
    exit 2
    ;;
esac

exec uv run --project "$project_root" --offline sbom-workbench selftest \
  --source-root "$source_root" \
  --active-source-root "$active_source_root" \
  --image-archive "$image_archive" \
  --portable-root "$portable_root" \
  --syft-bin "$syft_bin" \
  --syft-config "$syft_config" \
  --output-root "$output_root"
