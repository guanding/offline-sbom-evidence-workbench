#!/bin/sh
set -eu

# M7-3 cosign acquisition mirrors the Syft M3A pattern: one immutable GitHub
# release asset, one platform, one expected binary digest (cross-checked against
# the official cosign_checksums.txt), no global installation, no online signing.
# cosign is a single executable (no archive, no config file). key-based signing
# with --tlog-upload=false stays offline; keyless/Fulcio/Rekor are forbidden by
# signing.py's _assert_offline allowlist+denylist.
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version="3.1.2"
release_tag_sha="dc80df70da727f4abdd843640594025584a270ae"
binary_url="https://github.com/sigstore/cosign/releases/download/v${version}/cosign-darwin-arm64"
checksums_url="https://github.com/sigstore/cosign/releases/download/v${version}/cosign_checksums.txt"
expected_binary_sha256="dec1c3f802320b19c2fbcf2dc7bcfb3f258e1c181a046c23a1a074bdf932f10a"
tools_root="$project_root/runtime/tools"
target="$tools_root/cosign-${version}"
lock_dir="$tools_root/.cosign-${version}.acquisition.lock"
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
  printf '%s\n' "refusing acquisition: cosign asset is pinned to darwin_arm64" >&2
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
fi

if [ -e "$target" ] || [ -L "$target" ]; then
  printf '%s\n' "refusing overwrite: $target" >&2
  exit 1
fi

mkdir -p -- "$tools_root"
if ! mkdir -- "$lock_dir" 2>/dev/null; then
  printf '%s\n' "another cosign ${version} acquisition is active or left a lock: $lock_dir" >&2
  exit 1
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/sbom-workbench-cosign-${version}.XXXXXX")
checksums="$temporary_root/cosign_checksums.txt"
binary="$temporary_root/cosign-darwin-arm64"
stage=$(mktemp -d "$tools_root/.cosign-${version}.stage.XXXXXX")

fetch() {
  # --http1.1 avoids intermittent HTTP/2 PROTOCOL_ERROR on large GitHub assets.
  # --retry covers transient SSL_ERROR_SYSCALL on constrained networks.
  if [ -n "$explicit_proxy" ]; then
    env \
      -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
      -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
      /usr/bin/curl --disable --http1.1 \
        --fail --silent --show-error --location --max-redirs 5 \
        --proto '=https' --proto-redir '=https' --cacert "$ca_bundle" \
        --connect-timeout 20 --max-time 900 --retry 4 --retry-all-errors --retry-delay 5 \
        --proxy "$explicit_proxy" --output "$2" "$1"
  else
    env \
      -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
      -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
      /usr/bin/curl --disable --http1.1 \
        --fail --silent --show-error --location --max-redirs 5 \
        --proto '=https' --proto-redir '=https' --cacert "$ca_bundle" \
        --connect-timeout 20 --max-time 900 --retry 4 --retry-all-errors --retry-delay 5 \
        --output "$2" "$1"
  fi
}

fetch "$checksums_url" "$checksums"
fetch "$binary_url" "$binary"

if [ ! -f "$binary" ] || [ ! -s "$binary" ]; then
  printf '%s\n' "download did not produce a non-empty regular binary" >&2
  exit 1
fi

observed_binary_sha256=$(/usr/bin/shasum -a 256 "$binary" | /usr/bin/awk '{print $1}')
if [ "$observed_binary_sha256" != "$expected_binary_sha256" ]; then
  printf '%s\n' \
    "binary SHA-256 mismatch: expected $expected_binary_sha256, got $observed_binary_sha256" >&2
  exit 1
fi

# Cross-check against the official checksums.txt entry for this asset.
checksums_official=$(/usr/bin/grep -E "cosign-darwin-arm64$" "$checksums" | /usr/bin/awk '{print $1}' | head -n1)
if [ -z "$checksums_official" ] || [ "$checksums_official" != "$expected_binary_sha256" ]; then
  printf '%s\n' \
    "checksums.txt does not corroborate the pinned binary digest (official=${checksums_official:-MISSING})" >&2
  exit 1
fi

checksums_sha256=$(/usr/bin/shasum -a 256 "$checksums" | /usr/bin/awk '{print $1}')
cp -- "$binary" "$stage/cosign"
chmod 0555 "$stage/cosign"

version_output=$("$stage/cosign" version 2>/dev/null || true)
observed_version=$(printf '%s\n' "$version_output" | /usr/bin/awk -F': *' '$1 ~ /GitVersion/ {print $2; exit}')
observed_commit=$(printf '%s\n' "$version_output" | /usr/bin/awk -F': *' '$1 ~ /GitCommit/ {print $2; exit}')
if [ "$observed_version" != "v${version}" ] && [ "$observed_version" != "${version}" ]; then
  printf '%s\n' "binary version mismatch: expected ${version}, got ${observed_version:-UNKNOWN}" >&2
  exit 1
fi

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
  '  "schema_version": "cosign-acquisition-1.0",' \
  '  "status": "HASH_VERIFIED_BINARY_OBSERVED",' \
  "  \"acquired_at_utc\": \"$acquired_at_utc\"," \
  "  \"source_url\": \"$binary_url\"," \
  "  \"checksums_url\": \"$checksums_url\"," \
  "  \"release_tag_sha\": \"$release_tag_sha\"," \
  "  \"observed_commit\": \"${observed_commit:-UNKNOWN}\"," \
  "  \"binary_sha256_expected\": \"$expected_binary_sha256\"," \
  "  \"binary_sha256_observed\": \"$observed_binary_sha256\"," \
  "  \"checksums_sha256\": \"$checksums_sha256\"," \
  '  "binary_relative_path": "cosign",' \
  "  \"observed_version\": \"${observed_version:-UNKNOWN}\"," \
  "  \"proxy_mode\": \"$proxy_mode\"," \
  "  \"proxy_address\": $proxy_address_json," \
  "  \"ca_bundle_sha256\": \"$ca_bundle_sha256\"," \
  "  \"egress_policy\": \"$egress_policy\"," \
  "  \"network_config_sha256\": \"$network_config_sha256\"," \
  '  "boundary": "Acquisition identity only (sha256 + version); commit observed not pinned (annotated tag). Not release authority, CRA/prEN-7 conformity, or certification."' \
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
  "binary_sha256=$observed_binary_sha256" \
  "version=${observed_version:-UNKNOWN}" \
  "receipt=$target/acquisition-receipt.json"
