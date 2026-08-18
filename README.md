# Offline SBOM Evidence Workbench

离线、证据驱动的 SBOM 工作台。在没有客户源码的前提下，系统已经跑通项目自有合成样本、Yocto 官方公开构建，以及用户指定 `euvd-sbom-matcher` v2.3.0 的 M3A→M6A 本地工程自测。确定性证据链始终是主流程；Qwen/Gemma 只在最小冲突卡旁路做 shadow 评估。

当前发布候选为 **`0.5.0-rc.1`**；Python/wheel 元数据按 PEP 440 规范化显示为 `0.5.0rc1`。

## 开源许可证

由 Ding Guan 享有版权的项目源代码、文档，以及公开候选中的 `schemas/`、
`datasets/` 和 `fixtures/synthetic_orion/` 的 [45 个固定文件](release/project_owned_assets.sha256)，
均以 [Apache License 2.0](LICENSE) 提供，版权声明见 [NOTICE](NOTICE)。这些文件
已确认由 Ding Guan 独立创作且不含客户或第三方作品；数据登记中引用的第三方
事实、名称、商标、来源、工具、模型或制品不因本项目许可证而被再授权。该授权
也不自动覆盖第三方依赖、vendored specs、其他证据或 fixtures、模型/运行记录等
单独治理材料。当前状态及发布边界见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 2026-08-04：M3A→M6A 本地自测结果

- 成功根：`runtime/euvd-selftest-run-20260804-r2`；状态 `M3A_ROOT_AND_M4A_PACK_VERIFIED_OPEN_CANDIDATE`。
- 三个独立 profile：冻结 Python 源码、OCI 镜像归档、Windows portable runtime；分别保留 Syft JSON、CycloneDX JSON、SPDX 2.3 JSON，共 9 份 raw 输出。
- CycloneDX 观察数量：source 8、OCI 1,850、portable 139；三者不得相加成“组件总体”。
- 12 项实际 OPEN finding：6 项版本冲突与 6 项 stale portable runtime。
- Qwen 严格 schema/evidence 通过 4/12，Gemma 2/12；r3 的 24/24 模型 HTTP 响应均保存并重放 byte count、Base64 raw bytes 与 SHA-256，canonical payload 由评估文件之外的本地控制记录锚定；决定保持 `SHADOW_ONLY_HOLD`。
- OCI CycloneDX 已单向人工导入本地 EUVD matcher：1,850 行归并为 1,830 个唯一 identity，0 confirmed、19 review、1,821 unmatched。匹配不能反写 SBOM，也不自动形成 CRA Art.14 决定。
- 备份通过“备份目录之外、但仍在同一本地工作区”的 manifest SHA-256 锚验证并完成恢复；清理演练只把恢复副本移入可恢复隔离区，不是安全擦除、异机/WORM 锚或生产灾备证明。
- 截至 2026-08-04 13:20 CST 的交付前检查，只读 UI 运行于 `127.0.0.1:8876`，EUVD matcher 运行于 `127.0.0.1:8090`。这是易失运行观察；启动 UI 时必须使用终端输出的完整 fragment-token URL。

这些结果统一标为 `SELF_TEST_NOT_CUSTOMER_EVIDENCE`。它们证明本地机制能够运行和复验，不证明真实产品组件完整、制造商批准、正式 SBOM 发布、PRE-7/CRA 符合、CAB 结论或认证。

## 2026-08-06：M7–M9 证据链增强与真实平台验证

- **M7（不可抵赖证据链）**：sealed pack 现含 in-toto ITE-6 信封（subject 绑定 canonical reconciliation hash，predicate 覆盖 manifest/dashboard/run_id/classification/boundary，篡改 fail-closed）；cosign 离线签名框架（allowlist `--key`+verb 限定 + denylist identity-token/certificate/bundle/rekor/fulcio/oidc，强制 `--tlog-upload=false`）；`scan-source-only` 单面命令修本地模型 `cyclonedx-xml` 冒充 `.json` 被 matcher 拒收的痛点。配套 4 路并行调研 40 工具的 SBOM 工具市场报告（`docs/SBOM_TOOL_LANDSCAPE_UPGRADE_PLAN.md`）。
- **M8-1（VEX 可信声明摄取）**：消费外部可信 issuer 签发的 VEX `not_affected` 声明，双格式解析（CycloneDX VEX + OpenVEX）→ issuer allowlist + cosign 离线签名双信任锚 → exact-set 绑定 intake receipt。只消费不产出（避免厂商自证反模式）。
- **M8-2（命中收窄回流 lane）**：打破 `SBOM_TO_EUVD_ONLY` 单向，但走独立 lane（`euvd_handoff.py` 零改动）。4 方案对抗审查后选定 isolated-intake（唯一满足"不破坏单向 handoff"硬约束）。最严胜出（任一非 not_affected → RETAINED）+ purl-presence 门 + VEX 绑定重算。
- **M8-3（purl qualifier-aware）**：保留 arch/distro、剥 volatile（package-id），修 M8-2 v1 保守剥光导致的 over-narrowing。
- **M9-1/3（source-only 健壮性）**：syft `python-package-cataloger` 不读 `import` 语句 → 纯源码 Python 项目产出 0 组件 SBOM 且原流程不告警；M9 让"0 组件 Python 项目"成为显式可审计 finding。
- **M9-2（import 证据采集）**：确定性提取 `import` 语句，过滤 stdlib/相对/本地，与 SBOM 组件对比得 `apparent_gaps`（`AUXILIARY_NOT_SBOM`，不进 CycloneDX，不作合规判定）。
- **真实 EUVD 平台验证（阶段 C）**：EUVD v2.3.1 服务修复后，vuln-target 真实 SBOM **50 命中**（含 django@1.11.0 的 EUVD-2026-19687 CVSS 9.8），经 xlsx→hits.json adapter 喂入 `intake-narrowed`，**1 被真实 VEX not_affected 收窄、49 保留**，fail-closed 不变量全过（narrowed+not_narrowed==total / direction / fact_write / original_handoff_untouched）。诚实边界：handoff=DECLARED（非三面）、VEX issuer=新生成 key、matcher hits 无签名（v1 限制）。

这些结果同样标为 `SELF_TEST_NOT_CUSTOMER_EVIDENCE`。in-toto 信封 + cosign 签名是 non-repudiation 增强，**不外推**为 release / CRA / prEN-7 / CAB；签名是增强不是阻断（unsigned pack 仍 valid）。M9 import 证据是 AUXILIARY 观测，不修补 SBOM（syft catalogue 仍权威）。

## 当前交付状态

- Release A、Release B：`RECONCILIATION_CLOSED`，生成两种 SBOM 和不可覆盖的证据包；
- Conflict：`RECONCILIATION_OPEN`，展示相互冲突的 claim/evidence，不生成 SBOM；
- Yocto 6.0/6.0.2：各识别 33 个 runtime packages；361 个 native-SPDX rootfs 常规文件与制品逐字节一致，制品另有 2 个文件；逐组件 producer 均保持 `UNKNOWN`，因此固定为 `REFERENCE_RECONCILIATION_OPEN`；
- Yocto A→B：检测 4 个安装版本变化，包括 `libcrypto3`、`openssl-conf` 的 `3.5.6 → 3.5.7`；新 build 产生新 graph/SBOM candidate，旧候选不可复用；
- Orion A→B：可查看组件升级、关系变化和发布制品哈希变化；
- PRO-03B v1.4：可安全导入为人工/供应商 claim，但不会被当成构建包含证明；
- oMLX/Qwen/Gemma：adapter 默认关闭，主流程不依赖模型；
- 运行期：本地分析和格式验证不需要网络。
- M7：sealed pack 含 in-toto ITE-6 信封；cosign 离线签名框架（allowlist+denylist，强制 `--tlog-upload=false`）；scan-source-only 单面 CycloneDX 1.7 退路。cosign 3.1.2 已有本机 hash-pinned 获取与往返观察，但二进制和本机回执不进入公开 Python 制品，换机必须重新受控获取。
- M8：VEX 可信声明摄取（CycloneDX VEX + OpenVEX 双格式 + issuer allowlist）；命中收窄回流 lane（isolated-intake，单向 EUVD→工作台，最严胜出）；purl qualifier-aware 规范化。
- M9：source-only 0 组件 Python 项目告警；import 证据采集（apparent_gaps，AUXILIARY）。
- 真实平台验证：EUVD v2.3.1 真实 50 命中 → 1 VEX 收窄 + 49 保留，fail-closed 不变量全过。

合成结果标为 `SYNTHETIC_ENGINEERING_PASS_WITH_DECLARED_SCOPE`；公开 Yocto 结果标为 `PUBLIC_BUILD_REFERENCE_PIPELINE_PASS_OPEN_CANDIDATE`。后者证明真实公开制品的处理机制可运行，但仍不是客户产品证据、制造商 SBOM、ground truth、PRE-7/CRA 符合性结论、CAB 结论或认证。

## 立即运行

```bash
git clone <repository-url> offline-sbom-evidence-workbench
cd offline-sbom-evidence-workbench
uv sync --frozen
./scripts/build_demo.sh
./scripts/serve_demo.sh runtime/demo-data 8876
```

最后一条命令会显示带随机 fragment token 的本地 URL。服务仅绑定 `127.0.0.1`，并启用 Host/Origin、会话令牌、CSRF 和 DNS-rebinding 防护。

直接查看本次 M3A/M4A 结果：

```bash
cd /path/to/offline-sbom-evidence-workbench
uv run --offline sbom-workbench validate-selftest-root \
  --output-root runtime/euvd-selftest-run-20260804-r2
./scripts/serve_demo.sh runtime/euvd-selftest-run-20260804-r2/data 8876
```

公开候选的安装、合成演示、BYO 输入和安全边界见[公开用户指南](docs/USER_GUIDE.md)。

运行真实 Yocto M2（第一次为显式联网获取；之后分析与复验完全离线）：

```bash
cd /path/to/offline-sbom-evidence-workbench
./scripts/acquire_yocto_m2.sh runtime/yocto-public-references
./scripts/build_yocto_m2.sh runtime/yocto-public-references runtime/m2-demo-data
./scripts/serve_demo.sh runtime/m2-demo-data 8876
```

获取目录必须为空；文件不会被覆盖。macOS 需安装 `zstd`，扫描器只读取受控临时快照中的 tar stream，不把 archive 成员写入文件系统，也不跟随符号链接。

验证全部回归：

```bash
SBOM_WORKBENCH_REQUIRE_LOOPBACK_TESTS=1 PYTHONDONTWRITEBYTECODE=1 \
  uv run --offline python -B release/run_public_tests.py
```

当前源码树发现 **323 项** `unittest`。受控发布验证必须在可绑定 loopback
的主机设置 `SBOM_WORKBENCH_REQUIRE_LOOPBACK_TESTS=1`，提供经审核的 BYO
CycloneDX/SPDX specs、受控 PRO-03B fixture 以及本次构建的 wheel/sdist，并做到
**323 项通过、0 项跳过**。本地已按这一路径验证当前 RC。

显式 allowlist 生成的公开源码候选不携带权利受限材料，因此当前会明确跳过
20 项：6 项外部 PRO-03B fixture、2 项构建制品 smoke、11 项 BYO specs
验证，以及 1 项不随公开候选分发的历史 acquisition receipt。这里的 skip 只说明
边界按预期故障关闭，不能替代上述零跳过发布验证。另需执行
`sh scripts/test_built_artifacts.sh`；该脚本在临时目录构建 wheel/sdist、安装 wheel、
核对公开资源并拒绝 `vendor/specs` 混入。受限沙箱若禁止 loopback bind，9 项 Web
安全测试还会以明确原因跳过，该环境不得用于正式放行。

## 安装制品、BYO specs 与平台边界

- wheel/sdist 包含项目自有 `schemas/`、`datasets/` 和 `fixtures/synthetic_orion/`；安装后默认命令不依赖源码 checkout 的绝对路径。
- `vendor/specs/` 中冻结的 CycloneDX/SPDX 副本当前分发权利为 `NOT_APPROVED`，因此**不会**进入公开 wheel/sdist。安装态执行格式验证前，必须由操作者审核并提供 BYO 目录：`export SBOM_WORKBENCH_VENDOR_SPECS_ROOT=/path/to/reviewed/specs`。缺失、哈希不符或不安全路径均故障关闭；hash PASS 不产生权利或合规批准。
- 包元数据当前仅声明 CPython `3.12.x` 与 POSIX。核心合成/离线处理路径可在 POSIX 上运行；M3/M4 Syft 网络拒绝自测依赖 macOS `/usr/bin/sandbox-exec`，受控 Syft/cosign 获取脚本当前固定 Darwin ARM64。Windows 未支持，Linux 全链发布验证尚未完成。
- 冻结或扫描 EUVD 时，活动源码树必须通过 `--active-source-root` 或 `SBOM_WORKBENCH_EUVD_SOURCE_ROOT` 显式配置；未配置即故障关闭。外部 PRO-03B 回归 fixture 仅通过 `SBOM_WORKBENCH_PRO03B_TEMPLATE` 注入，不随公开制品分发。

验证已生成的证据包：

```bash
uv run --offline sbom-workbench validate-output \
  --run-directory runtime/demo-data/runs/<run-id> \
  --trusted-manifest-sha256 <独立保存的 manifest SHA-256>
```

复验公开 Yocto 候选包时，CLI 会强制核对仓库内冻结 Profile Registry 的 SHA-256，并从证据包内五个原始输入重新生成 graph：

```bash
uv run --offline sbom-workbench validate-reference-output \
  --run-directory runtime/m2-demo-data/runs/<yocto-run-id>
```

导入现有客户模板：

```bash
uv run --offline sbom-workbench import-pro03b \
  /absolute/path/to/PRO-03B_SBOM_HBOM最低字段客户填写模板_v1.4.xlsx
```

## 系统原则

```text
构建证据 lane ─┐
发布制品 lane ─┼─> evidence graph ─> component_population ─> 五态对账
人工/供应商 lane ┘                                      │
                                           OPEN ──> 人工复核包
                                           CLOSED ─> CDX + SPDX + evidence pack
```

每个导出事实都必须带 evidence ID；冲突并存、未知不猜；候选不能反向生成总体；两种格式从同一 canonical graph 分别原生导出。本地模型只能在旁路解释最小冲突卡，不能新增事实、改变状态或决定导出。

## 下一阶段

M3A–M6A 本地工程自测、M7 证据链增强（in-toto + cosign）、M8 漏洞响应链（VEX 摄取 + 命中收窄 + purl qualifier-aware）、M9 source-only 完整性观测（0 组件告警 + import 证据）均已完成，并经真实 EUVD v2.3.1 平台验证（50 命中 → 1 收窄 + 49 保留）。下一条主线仍是原 Yocto M3B：在一次性 Linux build VM 中对公开 Yocto layer 做本地受控构建，加入 package database/pkgdata/buildhistory、kernel/modules/bootloader/firmware 证据，并建立 recipe → package → rootfs file → release artifact 映射。

真实客户 M6 仍待具名客户、冻结产品 build、客户处理授权、独立组件总体和人工复核。当前 Qwen/Gemma 的严格输出合格率不足，不能升级出 shadow；在提示/schema 适配后须使用新预注册样本重评，不能覆盖本次失败证据。

权利、身份和制造商授权门按本次决策不阻断工程验证，但仍保留为任何客户数据接入、正式 SBOM 放行和对外合规主张的边界。

## 文档

- [公开用户指南](docs/USER_GUIDE.md)
- [合成 MVP 验收说明](docs/SYNTHETIC_MVP_ACCEPTANCE.md)
- [版本变更](CHANGELOG.md)
- [发布流程](RELEASE_PROCESS.md)
- [安全策略](SECURITY.md)
- [公开发布检查表](PUBLIC_RELEASE_CHECKLIST.md)
