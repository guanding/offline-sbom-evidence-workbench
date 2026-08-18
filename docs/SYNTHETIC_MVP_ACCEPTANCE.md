# Synthetic Orion MVP acceptance

> **SYNTHETIC_NOT_EVIDENCE** — 本页及其全部 Orion 资产仅用于本项目回归测试，不是客户证据、真实 SBOM、制造商发布记录、符合性结论或 CAB/认证结论。

## 验收目标

本 fixture 验证“固定 release 身份 + 两条独立 discovery lane + 冲突保留 + build-bound candidate”的最小技术链。它不验证真实产品组件完整性，也不把机械 PASS 升级为 CRA 或 prEN 40000 符合性。

当前依据为冻结的 CEN Enquiry 草案 `prEN 40000-1-3 Clause 5.3.8 [PRE-7]`，不是正式 EN 或协调标准。与本 fixture 直接相关的需求映射如下：

- `PRE-7-RQ-01/RQ-02`：识别组件并保存 producer、name、version；
- `PRE-7-RQ-03/RQ-03-RE`：至少覆盖 top-level，并为 transitive/component population 留出逐项事实；增强要求的适用性不由 fixture 决定；
- `PRE-7-RQ-04/RQ-07`：候选采用结构化 JSON，保存关系与唯一标识；本内部 candidate 不是对 SPDX/CycloneDX 合规性的声明；
- `PRE-7-RQ-05`：Release B 绑定新 build、制品、候选及被升级组件版本；
- `PRE-7-RQ-06`：release 绑定 SBOM author、version、ISO 8601 UTC timestamp 与 evidence cutoff；
- `PRE-7-RQ-07-RE`：仅在供应商同时提供 hash 与对应 algorithm 时保留二者。仅有 hash 的 `orion-telemetry` 明确保留 `algorithm: null`，不得猜测。

## 资产与物理隔离

```text
fixtures/synthetic_orion/
├── source/
│   ├── release-a/{recipe,payload}/
│   ├── release-b/{recipe,payload}/
│   └── conflict/{recipe,payload}/
├── tools/rebuild.py
├── release-a/{release.json,evidence/,candidate-sbom.json,artifacts/}
├── release-b/{release.json,evidence/,candidate-sbom.json,artifacts/}
├── conflict/{release.json,evidence/,candidate-sbom.json,artifacts/}
└── oracle/
```

每个 tar 只含项目自有的 `SYNTHETIC_NOT_EVIDENCE.txt` 与 `artifact-inventory.json`，不含第三方代码、第三方二进制或客户资料。`tools/rebuild.py` 只读取对应 `source/<case>/payload/`，按 UTF-8 路径排序，并固定 tar 的 mode、uid、gid、uname、gname 与 mtime；它不读取答案区。

重建示例：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 fixtures/synthetic_orion/tools/rebuild.py \
  --release release-a \
  --output /tmp/orion-release-a.tar
```

## 两条 discovery lane

| Lane | 手写 evidence | 独立事实源 | 禁止事项 |
| --- | --- | --- | --- |
| build-manifest | `evidence/build-manifest.json` | 项目自有 `source/<case>/recipe/build-descriptor.json` | 不读取最终 tar 内 inventory，不读取 candidate |
| artifact-inventory | `evidence/artifact-inventory.json` | 最终确定性 tar 内 marker 与 inventory | 不读取 build descriptor，不读取 candidate |

两份 evidence 均标记 `HUMAN_AUTHORED_PROJECT_SYNTHETIC`。测试分别将 build lane 与 build descriptor 比对，并从 tar 中独立读取 artifact inventory 后比对；仅检查两个 JSON 文本不同不算独立性证明。

## 覆盖矩阵

| 场景 | Fixture 表达 | 预期处理 |
| --- | --- | --- |
| root product | candidate 顶层 `producer/name/version/identifiers`，含 `COMPONENT_ROLE=ROOT_PRODUCT` | 不在 components 中重复根产品 |
| top-level | `orion-app`、`orion-telemetry` | 保留为 `TOP_LEVEL` |
| transitive | `orion-crypto`、两个 transport 实例 | 保留为 `TRANSITIVE` |
| binary-only firmware | `orion-radio-fw`，`source_available=false` | 不因无源码而删除 |
| 同名同版本、不同来源/哈希 | `orion-transport-source` 与 `orion-transport-binary` | candidate ID 保持不同，不按 name/version 合并 |
| supplier hash + algorithm | `orion-radio-fw` | 保存 `SUPPLIER_HASH` + `SHA-256` |
| 仅 supplier hash、无 algorithm | `orion-telemetry` | 保存 hash 且 algorithm 为 null；限制项保持可见 |
| UNKNOWN | conflict 的 binary-only `orion-unknown-blob` | discovery 身份字段保留显式 `UNKNOWN`；candidate 映射为 null；状态保持 OPEN |

## A/B 与冲突预期

Release A 与 Release B 保持 manufacturer、product、architecture、hardware revision 与制品相对路径不变。发布事件字段可变化；依赖组件图只允许：

1. `orion-crypto` 从 `1.0.0` 升级为 `1.1.0`，其 observed SHA-256 同步变化；
2. 关系列表仅 index 1 从 `DEPENDS_ON` 变化为 `GENERATED_FROM`；其他组件及关系逐项相同。

A/B 的候选技术状态为 `SYNTHETIC_RECONCILED`。这只表示两条 synthetic lane 对该固定 fixture 一致；不表示实际 SBOM 完整、PRE-7 符合、产品发布或合格评定。

Conflict case 中，build descriptor 将 `orion-crypto` 记录为 `1.0.0`，最终 tar inventory 将其记录为 `9.9.9-artifact-conflict`，并额外观察到身份未知的 hashed slot。候选不得择一猜测：组件版本为 null、冲突 `resolution` 为 null、总体状态为 `SYNTHETIC_RECONCILIATION_OPEN`。

## Hash 与 exact-set

每个 `release.json` 直接绑定：

- 固定 `artifact_relative_path` 与实际 tar SHA-256；
- 两个固定 evidence 相对路径及各自文件 SHA-256；
- release/build/product/hardware/time/author/version/cutoff 身份。

每个 release package 的 exact-set 根仅包含五个文件：tar、candidate、两份 evidence、release。验收答案放在 `fixtures/synthetic_orion/oracle/`，位于 package root 外；source 与 rebuild 工具也不进入 runtime exact-set。测试复用 Evidence Manifest v1 的 `root_id + sorted file records` 算法，将重算结果与答案区比对，并扫描 runtime JSON，拒绝任何答案区路径或名称引用。

## 状态边界

candidate 只允许：

- `SYNTHETIC_RECONCILED`
- `SYNTHETIC_RECONCILIATION_OPEN`

并强制：

- `classification = SYNTHETIC_NOT_EVIDENCE`
- `product_conformity_status = NO_PRODUCT_CONFORMITY_STATUS`
- `manufacturer_release_authority = false`
- `cab_conclusion = false`

`C/PC/NC/NA`、`COMPLIANT`、`APPROVED`、`RELEASED`、`CERTIFIED` 或类似制造商/CAB 状态均不得出现在候选状态字段或 schema 枚举中。

## 执行

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.test_synthetic_fixture -v
```

通过表示 fixture 的结构、哈希、重建确定性、lane 隔离和 fail-closed 状态边界符合本文件；它不替代独立语义评审、真实项目 evidence review 或制造商决定。
