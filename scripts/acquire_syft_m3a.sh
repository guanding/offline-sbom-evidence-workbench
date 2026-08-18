#!/bin/sh
set -eu

# M3A scanner acquisition is deliberately narrow: one immutable GitHub release
# asset, one platform, one expected archive digest, and no global installation.
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version="1.50.0"
release_commit="16223e6dd7893fe578787658ceb876257483d404"
asset_url="https://github.com/anchore/syft/releases/download/v${version}/syft_${version}_darwin_arm64.tar.gz"
expected_archive_sha256="e32fdb9d47823fa633748a1efca2528fd77c37469ea93c9e40ab835da44e4cce"
tools_root="$project_root/runtime/tools"
target="$tools_root/syft-${version}"
lock_dir="$tools_root/.syft-${version}.acquisition.lock"
ca_bundle="/etc/ssl/cert.pem"
explicit_proxy=${SBOM_ACQUISITION_HTTPS_PROXY:-}
temporary_root=""
stage=""

cleanup() {
  if [ -n "$stage" ] && [ -d "$stage" ]; then
    rm -rf -- "$stage"
  fi
  if [ -n "$temporary_root" ] && [ -d "$temporary_root" ]; then
    rm -rf -- "$temporary_root"
  fi
  if [ -d "$lock_dir" ]; then
    rmdir -- "$lock_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  printf '%s\n' "refusing acquisition: Syft asset is pinned to darwin_arm64" >&2
  exit 1
fi
if [ ! -f "$ca_bundle" ] || [ -L "$ca_bundle" ]; then
  printf '%s\n' "refusing acquisition: fixed CA bundle is unavailable or is a symlink: $ca_bundle" >&2
  exit 1
fi
if [ -n "$explicit_proxy" ]; then
  if ! printf '%s\n' "$explicit_proxy" | /usr/bin/grep -Eq '^http://(127\.0\.0\.1|localhost):[0-9]{1,5}$'; then
    printf '%s\n' \
      "SBOM_ACQUISITION_HTTPS_PROXY must be an explicit credential-free loopback HTTP proxy" >&2
    exit 1
  fi
  proxy_port=${explicit_proxy##*:}
  if [ "$proxy_port" -gt 65535 ]; then
    printf '%s\n' "SBOM_ACQUISITION_HTTPS_PROXY port is outside 1..65535" >&2
    exit 1
  fi
fi

if [ -e "$target" ] || [ -L "$target" ]; then
  printf '%s\n' "refusing overwrite: $target" >&2
  exit 1
fi

mkdir -p -- "$tools_root"
if ! mkdir -- "$lock_dir" 2>/dev/null; then
  printf '%s\n' "another Syft ${version} acquisition is active or left a lock: $lock_dir" >&2
  exit 1
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/sbom-workbench-syft-${version}.XXXXXX")
archive="$temporary_root/syft_${version}_darwin_arm64.tar.gz"
stage=$(mktemp -d "$tools_root/.syft-${version}.stage.XXXXXX")

# --disable prevents ~/.curlrc from changing this request. Host proxy variables
# are always removed. A proxy is usable only through the explicit, validated
# SBOM_ACQUISITION_HTTPS_PROXY input and is recorded in the receipt.
if [ -n "$explicit_proxy" ]; then
  env \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
    -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    /usr/bin/curl --disable \
      --fail --silent --show-error --location --max-redirs 5 \
      --proto '=https' --proto-redir '=https' --cacert "$ca_bundle" \
      --connect-timeout 20 --max-time 600 --retry 2 --retry-all-errors \
      --proxy "$explicit_proxy" --output "$archive" "$asset_url"
else
  env \
    -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
    -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
    /usr/bin/curl --disable \
      --fail --silent --show-error --location --max-redirs 5 \
      --proto '=https' --proto-redir '=https' --cacert "$ca_bundle" \
      --connect-timeout 20 --max-time 600 --retry 2 --retry-all-errors \
      --output "$archive" "$asset_url"
fi

if [ ! -f "$archive" ] || [ ! -s "$archive" ]; then
  printf '%s\n' "download did not produce a non-empty regular archive" >&2
  exit 1
fi

observed_archive_sha256=$(/usr/bin/shasum -a 256 "$archive" | /usr/bin/awk '{print $1}')
if [ "$observed_archive_sha256" != "$expected_archive_sha256" ]; then
  printf '%s\n' \
    "archive SHA-256 mismatch: expected $expected_archive_sha256, got $observed_archive_sha256" >&2
  exit 1
fi

# Extraction and execution happen only after the fixed archive digest matches.
# Extracting the single expected member also prevents unrelated archive entries
# from entering the runtime directory.
/usr/bin/tar -xzf "$archive" -C "$stage" syft
if [ ! -f "$stage/syft" ] || [ -L "$stage/syft" ]; then
  printf '%s\n' "verified archive did not yield a regular syft executable" >&2
  exit 1
fi
chmod 0555 "$stage/syft"

# This minimal checked runtime configuration disables Syft's update lookup.
# Scan-time source enrichment is additionally disabled by the selftest runner.
printf '%s\n' \
  'check-for-app-update: false' \
  > "$stage/syft-m3a.yaml"
chmod 0444 "$stage/syft-m3a.yaml"

version_output=$(SYFT_CHECK_FOR_APP_UPDATE=false \
  "$stage/syft" version --config "$stage/syft-m3a.yaml")
observed_version=$(printf '%s\n' "$version_output" | /usr/bin/awk -F': *' '$1 == "Version" {print $2; exit}')
observed_commit=$(printf '%s\n' "$version_output" | /usr/bin/awk -F': *' '$1 == "GitCommit" {print $2; exit}')
observed_platform=$(printf '%s\n' "$version_output" | /usr/bin/awk -F': *' '$1 == "Platform" {print $2; exit}')
if [ "$observed_version" != "$version" ]; then
  printf '%s\n' "binary version mismatch: expected $version, got ${observed_version:-UNKNOWN}" >&2
  exit 1
fi
if [ "$observed_commit" != "$release_commit" ]; then
  printf '%s\n' \
    "binary commit mismatch: expected $release_commit, got ${observed_commit:-UNKNOWN}" >&2
  exit 1
fi
if [ "$observed_platform" != "darwin/arm64" ]; then
  printf '%s\n' "binary platform mismatch: expected darwin/arm64, got ${observed_platform:-UNKNOWN}" >&2
  exit 1
fi

binary_sha256=$(/usr/bin/shasum -a 256 "$stage/syft" | /usr/bin/awk '{print $1}')
config_sha256=$(/usr/bin/shasum -a 256 "$stage/syft-m3a.yaml" | /usr/bin/awk '{print $1}')
ca_bundle_sha256=$(/usr/bin/shasum -a 256 "$ca_bundle" | /usr/bin/awk '{print $1}')
egress_policy="FIXED_GITHUB_RELEASE_HTTPS_URL_HTTPS_REDIRECTS_MAX_5"
if [ -n "$explicit_proxy" ]; then
  proxy_mode="EXPLICIT_LOOPBACK"
  proxy_address_json="\"$explicit_proxy\""
else
  proxy_mode="DIRECT_NO_INHERITED_PROXY"
  proxy_address_json="null"
fi
network_config_sha256=$(printf '%s\n' \
  "proxy_mode=$proxy_mode" \
  "proxy_address=$explicit_proxy" \
  "ca_bundle_sha256=$ca_bundle_sha256" \
  "egress_policy=$egress_policy" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')
acquired_at_utc=$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')

printf '%s\n' \
  '{' \
  '  "schema_version": "m3a-runtime-acquisition-1.0",' \
  '  "status": "ARCHIVE_HASH_VERIFIED_BINARY_OBSERVED",' \
  "  \"acquired_at_utc\": \"$acquired_at_utc\"," \
  "  \"source_url\": \"$asset_url\"," \
  "  \"resolved_commit\": \"$release_commit\"," \
  "  \"archive_sha256_expected\": \"$expected_archive_sha256\"," \
  "  \"archive_sha256_observed\": \"$observed_archive_sha256\"," \
  '  "binary_relative_path": "syft",' \
  "  \"binary_sha256\": \"$binary_sha256\"," \
  '  "config_relative_path": "syft-m3a.yaml",' \
  "  \"config_sha256\": \"$config_sha256\"," \
  "  \"observed_version\": \"$observed_version\"," \
  "  \"proxy_mode\": \"$proxy_mode\"," \
  "  \"proxy_address\": $proxy_address_json," \
  "  \"ca_bundle_sha256\": \"$ca_bundle_sha256\"," \
  "  \"egress_policy\": \"$egress_policy\"," \
  "  \"network_config_sha256\": \"$network_config_sha256\"," \
  '  "dependency_manifest_status": "NOT_ACQUIRED",' \
  '  "boundary": "Acquisition identity only; not reproducible-build, scan completeness, release, manufacturer authorization, or conformity evidence."' \
  '}' \
  > "$stage/acquisition-receipt.json"
chmod 0444 "$stage/acquisition-receipt.json"

if [ -e "$target" ] || [ -L "$target" ]; then
  printf '%s\n' "target appeared during acquisition; refusing overwrite: $target" >&2
  exit 1
fi
mv -- "$stage" "$target"
stage=""

printf '%s\n' \
  "status=ACQUIRED_HASH_VERIFIED" \
  "target=$target" \
  "archive_sha256=$observed_archive_sha256" \
  "binary_sha256=$binary_sha256" \
  "config_sha256=$config_sha256" \
  "version=$observed_version" \
  "receipt=$target/acquisition-receipt.json"
