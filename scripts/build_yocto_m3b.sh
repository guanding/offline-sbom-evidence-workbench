#!/bin/sh
# M3B local build + evidence collection (skeleton).
# REQUIRES_LINUX_BUILD_VM — 在一次性 Linux build VM（Ubuntu 24.04 ARM64）内执行。
# macOS 主机不能原生 Yocto 构建；本脚本仅作骨架评审与文档维护。
#
# 输入：acquire_yocto_m3b.sh 产出的 source mirror（poky + boundary layer + DL_DIR）。
# 输出：core-image-minimal + hello-mod 构建产物 + 7 类 evidence lane 采集。
#
# 详见 docs/M3B_EXECUTION_PLAN.md（§4 VM 规格 / §5 离线约束 / §6 evidence lane /
# §11 验收门）。
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

mirror_root=${1:-"$project_root/runtime/yocto-m3b-mirror"}
data_root=${2:-"$project_root/runtime/m3b-demo-data"}

# 容量预检（fail-closed；见 §4）
min_disk_gb=150
min_mem_gb=32
min_cores=8

printf '%s\n' "M3B local build (skeleton) — REQUIRES_LINUX_BUILD_VM"
printf '%s\n' "mirror=$mirror_root"
printf '%s\n' "data=$data_root"

# --- 以下步骤在 Linux build VM 内执行（macOS 主机会失败）---------------------
# 0. 容量预检（不足则拒绝构建）：
#      disk_free=$(df -m / | awk 'NR==2{print $4}'); [ "$disk_free" -ge $((min_disk_gb*1024)) ] || exit 1
#      mem_mb=$(free -m | awk '/^Mem:/{print $2}');   [ "$mem_mb" -ge $((min_mem_gb*1024)) ] || exit 1
#      cores=$(nproc);                                 [ "$cores" -ge "$min_cores" ] || exit 1
#
# 1. 离线约束（见 §5 五条硬约束）：
#      - 虚拟网卡禁用或 host-only（ip link set <nic> down）
#      - 外联监测启动：tcpdump -i any -w "$data_root/egress.pcap" -U &
#      - export BB_NO_NETWORK=1
#      - 确认无 SRCREV="${AUTOREV}"（grep -r 'AUTOREV' "$mirror_root" 应无命中）
#
# 2. 构建配置（local.conf 关键项）：
#      MACHINE = "qemuarm64"
#      DL_DIR = "$mirror_root/downloads"
#      INHERIT += "create-spdx-3.0 buildhistory"
#      SPDX_INCLUDE_KERNEL_CONFIG = "1"
#      SPDX_INCLUDE_PACKAGECONFIG = "1"
#      BB_NO_NETWORK = "1"
#      IMAGE_INSTALL:append = " hello-mod"
#
# 3. 构建：
#      cd "$mirror_root/poky" && source oe-init-build-env "$data_root/build"
#      bitbake core-image-minimal hello-mod
#
# 4. evidence lane 采集（见 §6 七类；每类带 evidence ID + 来源 + 工具版本 + SHA-256）：
#      - pkgdata        : tmp/pkgdata/qemuarm64/
#      - buildhistory   : buildhistory/
#      - package DB     : tmp/pkgdb/（若启用）
#      - create-spdx-3.0: tmp/deploy/spdx/
#      - kernel/modules : tmp/deploy/images/qemuarm64/（kernel + modules.tar + DTB）
#      - bootloader     : tmp/deploy/images/qemuarm64/（若 image 含）
#      - firmware       : rootfs /lib/firmware/（清单 + hash）
#
# 5. recipe → package → rootfs file → release artifact 映射（见 §7 四层链）：
#      TODO: 工作台 M3B 映射器（待实现）从 pkgdata + buildhistory + rootfs manifest 派生。
#
# 6. 外联监测审计：
#      构建后审计 egress.pcap；任何非预期外联 = 构建无效（exit 1）。
#
# 7. 工作台 CLI（待实现）：
#      uv run --project "$project_root" --offline sbom-workbench yocto-m3b-demo \
#        --mirror "$mirror_root" --data-root "$data_root"
#      生成 canonical graph + 双格式导出 + evidence pack（复用 M2 pipeline）。
#
# 8. 验收门 checklist（见 §11）：
#      由工作台 CLI + 人工（双路径标注 + 第三人裁决 oracle）共同判定。
#      全过 → FIXTURE_GROUND_TRUTH_WITH_DECLARED_SCOPE；任一未过 → REFERENCE_RECONCILIATION_OPEN。
# ----------------------------------------------------------------------------

printf '%s\n' "skeleton complete — actual build requires Linux build VM (see comments above)"
