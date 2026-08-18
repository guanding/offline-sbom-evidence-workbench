# Third-party material register

**Source repository status: APPROVED WITH EXCLUSIONS. Artifact distribution
status: BLOCKED / NOT OFFERED.**

This register distinguishes public Git source from separately distributed
dependencies, packages, and other artifacts. It is not a license grant, legal
opinion, compatibility decision, or authorization to redistribute an external
item.

## Project-owned material

Source code, documentation, and the release assets under `schemas/`,
`datasets/`, and `fixtures/synthetic_orion/` are owned by Ding Guan and licensed
under the Apache License 2.0; see `LICENSE`, `NOTICE`, `pyproject.toml`, and the
45-file exact-byte record in `release/project_owned_assets.sha256`. On
2026-08-17, the copyright holder confirmed that the listed files were
independently authored and contain no customer or third-party work. For dataset
records, Apache-2.0 covers the project's original structure, selection, and
annotations; it does not relicense referenced third-party facts, names,
trademarks, source locations, tools, models, or artifacts. The project license
also does not grant rights to dependencies, vendored specifications, other
evidence or fixtures, or other separately governed material listed below.

## Declared Python dependencies

| Package | Locked direct version | Rights status |
| --- | --- | --- |
| jsonschema | 4.26.0 | License and notice review required |
| pySHACL | 0.40.1 | License and transitive-dependency review required |

`uv.lock` records the runtime set and hashes. `requirements-ci.lock` separately
records the hash-locked `uv`, `ruff`, and `pip-audit` tool graph, while
`pyproject.toml` pins the setuptools build backend. These records are not
license inventories. The CI-generated metadata report is informational only;
package metadata is not a substitute for reviewing authoritative license
texts, notices, source-offer obligations, or compatibility with the project's
Apache-2.0 license.

## Vendored validation specifications

The authoritative local status remains the per-artifact
`vendor/specs/SOURCE_MANIFEST.json`:

| Artifact | Candidate license field | Current distribution status |
| --- | --- | --- |
| CycloneDX 1.7 JSON Schema | `Apache-2.0` candidate | `NOT_APPROVED`; excluded from public source and artifacts |
| SPDX 3.0.1 JSON Schema | `LICENSE_REVIEW_REQUIRED` | `NOT_APPROVED`; excluded from public source and artifacts |
| SPDX 3.0.1 JSON-LD context | `LICENSE_REVIEW_REQUIRED` | `NOT_APPROVED`; excluded from public source and artifacts |
| SPDX 3.0.1 ontology/SHACL model | `LICENSE_REVIEW_REQUIRED` | `NOT_APPROVED`; excluded from public source and artifacts |

Technical identity, a source URL, or a matching SHA-256 does not grant
redistribution permission. These files must be removed from public artifacts,
acquired separately at installation/runtime under approved terms, or released
only after the rightsholder and notice obligations are documented for the exact
artifact.

## Evidence, datasets, fixtures, manuals, and tools

The 45 exact files under the allowlisted `schemas/`, `datasets/`, and
`fixtures/synthetic_orion/` paths have the project-owned decision recorded
above. A changed or additional file is unapproved until the manifest and rights
decision are explicitly renewed. Other tracked `evidence/` and `fixtures/`,
Office/PDF documents, rendered images, acquisition receipts, local-model
observations outside that manifest, and generated reports require item-level
review for source rights, customer/personal data, local paths, metadata,
trademarks, and redistribution scope. “Synthetic” or “self-test” labels alone
are not rights approval.

GitHub Actions and the pinned `uv` build frontend also require source/license
recording in the final exact dependency and tool manifest. If an OCI artifact
is introduced, its base images, tools, package layers, licenses, notices, SBOM,
and vulnerability status enter the same release gate.

## Required release evidence

Before changing this status, attach to the fixed release commit:

1. the exact direct and transitive dependency set with hashes;
2. authoritative license texts and required notices;
3. a compatibility/obligations review;
4. a source and rights decision for every vendored spec and tracked asset;
5. the maintainer, date, scope, review model, and exact approved hashes.
