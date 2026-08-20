# Public user guide

This guide covers the public-source candidate of Offline SBOM Evidence
Workbench. The current candidate is an engineering RC, not a released package,
customer evidence, a manufacturer-approved SBOM, or a conformity decision.

## Supported lane

- CPython 3.12.x on POSIX.
- `uv` using the checked-in `uv.lock`.
- Local loopback access for the browser interface.

Windows is unsupported. The complete Linux release lane is still pending. Some
network-denial and controlled acquisition helpers are currently macOS-specific.

## Graphical source-to-SBOM workflow

The graphical workflow is local-only and can start without an evidence data
directory. In a macOS Apple Silicon source checkout, acquire the fixed scanner
once while network access is intentionally enabled:

```bash
./scripts/acquire_syft_m3a.sh
```

The acquisition helper accepts only the pinned Syft 1.50.0 Darwin ARM64
release archive, verifies its fixed SHA-256 before extraction, observes the
binary version and commit, and records a local acquisition receipt. Subsequent
scans run offline under macOS `sandbox-exec` with network access denied.

Start generation-only mode:

```bash
uv run --offline sbom-workbench serve --port 8765
```

Open only the complete fragment-token URL printed in the terminal. Then:

1. Enter a project/product name and version or snapshot label. These are
   operator declarations, not independently verified release identity.
2. Select individual files or one directory. The browser sends relative paths
   and selected bytes to a server-owned temporary directory; it never sends an
   arbitrary host filesystem path.
3. Choose the preferred format and start the scan. The preferred output is
   listed first, but all supported JSON formats are generated.
4. Review the coverage and component-population gates before downloading.
5. Download CycloneDX JSON, SPDX JSON, Syft JSON, and the scan evidence receipt.
   The browser re-hashes every download and refuses to save a mismatch.
6. Select **clear temporary data**, or stop the server, when finished.

The scan receipt binds each untouched raw scanner artifact hash to its
downloadable privacy-projected hash, plus the source exact-set, completion
anchor, scanner policy, and independent validation gates. Privacy projection
performs string substitution only; it cannot add, delete, or infer components.
Known session/runtime roots and user-home prefixes are replaced, and any
remaining recognized user-specific path blocks all downloads.

The intake limits are 10,000 files, 1 GiB total selected bytes, 256 MiB per
file, and 64 path segments. One local worker processes at most eight session
jobs; no browser upload is forwarded to a network service. Browser selection
does not preserve symlink or hard-link identity, ownership, or executable bits.
Use the governed CLI acquisition lane when those filesystem semantics matter.

`VALID_WITH_COVERAGE_HOLD` means the JSON and source binding validated while
coverage or component-population review remains open. It is not a release
quality PASS. All graphical outputs are source-only candidates, not product
completeness evidence, a manufacturer-approved SBOM, PRE-7/CRA conformity, a
CAB conclusion, or certification.

### Installed wheel or explicit scanner paths

The public wheel deliberately does not contain the Syft executable. When the
three runtime files are outside a source checkout, configure them atomically:

```bash
sbom-workbench serve \
  --syft-bin /reviewed/runtime/syft \
  --syft-config /reviewed/runtime/syft-m3a.yaml \
  --syft-receipt /reviewed/runtime/acquisition-receipt.json \
  --port 8765
```

Supplying only part of that tuple fails closed. The packaged runtime registry
remains the default; `--runtime-registry` is available only when an explicitly
reviewed replacement is required. `--disable-scanning` intentionally starts
the evidence viewer with generation disabled.

## Clean-clone synthetic demonstration

```bash
git clone <repository-url> offline-sbom-evidence-workbench
cd offline-sbom-evidence-workbench
uv sync --frozen
./scripts/build_demo.sh
./scripts/serve_demo.sh runtime/demo-data 8876
```

Open only the fragment-token URL printed by `serve_demo.sh`. The service binds
to `127.0.0.1`; do not expose it to a LAN or the internet as an authentication
system.

The generated Orion material is marked `SYNTHETIC_NOT_EVIDENCE`. It exercises
the deterministic graph, reconciliation, export, and verification paths but
does not establish completeness or suitability for a real product.

## Tests and package artifacts

Run the public-source lane:

```bash
sh scripts/test_public_source.sh
```

The public allowlist intentionally excludes reviewed-separately inputs. The
current RC therefore reports 20 explicit skips: 6 external PRO-03B fixture
tests, 2 built-artifact tests, 11 BYO specification tests, and 1 historical
acquisition-receipt test. No unexplained skip is acceptable.
The runner fails if either the skip count or any skip reason changes.
The exact public-source count for this candidate is 383 tests.
The wrapper creates its virtual environment outside the source/candidate tree
and, when a public manifest is present, verifies the exact set before and after
testing so build metadata cannot silently mutate the candidate.

Build and verify wheel/sdist after the environment and build frontend are
available:

```bash
sh scripts/test_built_artifacts.sh
```

The artifact test installs the wheel outside the checkout, verifies
project-owned offline resources, and rejects accidental `vendor/specs`
inclusion.

## BYO specification boundary

Frozen CycloneDX/SPDX copies under the private development tree are not
approved for redistribution and are absent from public source, wheel, and
sdist candidates. To exercise specification-backed validators, provide a
separately reviewed directory explicitly:

```bash
export SBOM_WORKBENCH_VENDOR_SPECS_ROOT=/absolute/path/to/reviewed/specs
```

Missing files, unexpected hashes, unsafe paths, or an unset variable fail
closed. A successful hash check is integrity evidence only; it is not a rights,
release, or conformity approval.

The controlled PRO-03B regression fixture is likewise external:

```bash
export SBOM_WORKBENCH_PRO03B_TEMPLATE=/absolute/path/to/reviewed/template.xlsx
```

## EUVD periodic component rescan handoff

The EUVD handoff receipt schema is `1.1`. It binds the immutable CycloneDX
bytes to a one-way `PERIODIC_COMPONENT_RESCAN_CANDIDATE_ONLY` purpose and states
that vulnerability confirmation and version applicability remain manual. The
EUVD Web intake validates this receipt fail-closed and forces rule-level
matches into manual-review candidate status. The paired EUVD Local Mirror can
also emit observations from a pure CycloneDX
`components[]` array, including top-level CPE and Syft `syft:cpe23` properties.

The resulting product-name candidates are monitoring leads only. A missing
candidate is not proof of no vulnerability, and a KEV candidate is not a CRA
Article 14 decision. Configure scan frequency, event-driven triggers, evidence
retention, and review ownership in the manufacturer's vulnerability-handling
policy; this tool deliberately does not invent a universal interval.

## Release boundary

Before publishing, complete [`../PUBLIC_RELEASE_CHECKLIST.md`](../PUBLIC_RELEASE_CHECKLIST.md)
for one fixed commit and artifact set. In particular, close the OSS license and
third-party rights decisions, run the controlled zero-skip lane, enable the
GitHub security gates, reproduce the package on each supported platform, and
obtain independent review. CI, hashes, an SBOM, or a signature alone do not
authorize release or customer delivery.
