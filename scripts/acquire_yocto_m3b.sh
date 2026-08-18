#!/bin/sh
# M3B source mirror acquisition (skeleton).
# REQUIRES_LINUX_BUILD_VM — 在一次性 Linux build VM（Ubuntu 24.04 ARM64）内执行。
# macOS 主机不能原生 Yocto 构建；本脚本仅作骨架评审与文档维护。
#
# 一次性联网：clone 固定 commit poky + 自有 boundary layer + 预获取 source tarball 到
# DL_DIR（hash-pinned exact-set）。之后构建完全离线（见 build_yocto_m3b.sh BB_NO_NETWORK=1）。
#
# 详见 docs/M3B_EXECUTION_PLAN.md（§3 冻结 profile / §5 离线约束 / §12 脚本骨架）。
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# 冻结 MVP profile（与 docs/M3B_EXECUTION_PLAN.md §3 一致）
poky_commit="5d1aa5c806c061a2994f4decb59016610f093213"   # Yocto 6.0.2 oe-core
poky_url="https://git.yoctoproject.org/git/poky"
# 自有 boundary layer（hello-mod + seeded 升级）—— TODO 固定仓库与 commit 后填入
boundary_layer_url="https://example.invalid/meta-sbom-workbench-boundary.git"
boundary_commit="0000000000000000000000000000000000000000"

mirror_root=${1:-"$project_root/runtime/yocto-m3b-mirror"}
poky_dir="$mirror_root/poky"
boundary_dir="$mirror_root/meta-sbom-workbench-boundary"
dl_dir="$mirror_root/downloads"

# no-overwrite（与 m2 脚本一致）
if [ -d "$mirror_root" ] && [ -n "$(ls -A "$mirror_root" 2>/dev/null)" ]; then
  printf '%s\n' "refusing overwrite: $mirror_root not empty" >&2
  exit 1
fi
mkdir -p "$mirror_root"

printf '%s\n' "M3B source mirror acquisition (skeleton) — REQUIRES_LINUX_BUILD_VM"
printf '%s\n' "target=$mirror_root"
printf '%s\n' "poky_commit=$poky_commit"
printf '%s\n' "boundary_commit=$boundary_commit"

# --- 以下步骤在 Linux build VM 内执行（macOS 主机会失败）---------------------
# 1. clone poky 固定 commit（禁 shallow，便于审计）：
#      git clone "$poky_url" "$poky_dir"
#      git -C "$poky_dir" checkout "$poky_commit"
#      observed=$(git -C "$poky_dir" rev-parse HEAD)
#      [ "$observed" = "$poky_commit" ] || { echo "poky commit mismatch"; exit 1; }
#
# 2. clone 自有 boundary layer（hello-mod + seeded 升级）：
#      git clone "$boundary_layer_url" "$boundary_dir"
#      git -C "$boundary_dir" checkout "$boundary_commit"
#
# 3. 预获取 source tarball 到 DL_DIR（一次性联网；之后 BB_NO_NETWORK=1）：
#      cd "$poky_dir" && source oe-init-build-env "$mirror_root/build"
#      DL_DIR="$dl_dir" bitbake core-image-minimal hello-mod --runall=fetch
#
# 4. 生成 acquisition receipt（mirror exact-set sha256 + 各 commit + DL_DIR 清单）：
#      TODO: 调工作台 CLI M3B acquire 子命令（待实现）生成 hash-pinned receipt，
#      作为 build 阶段离线构建的信任根。
# ----------------------------------------------------------------------------

printf '%s\n' "skeleton complete — actual fetch requires Linux build VM (see comments above)"
