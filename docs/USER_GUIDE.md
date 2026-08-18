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
SBOM_WORKBENCH_REQUIRE_LOOPBACK_TESTS=1 PYTHONDONTWRITEBYTECODE=1 \
  uv run --offline python -B release/run_public_tests.py
```

The public allowlist intentionally excludes reviewed-separately inputs. The
current RC therefore reports 20 explicit skips: 6 external PRO-03B fixture
tests, 2 built-artifact tests, 11 BYO specification tests, and 1 historical
acquisition-receipt test. No unexplained skip is acceptable.
The runner fails if either the skip count or any skip reason changes.

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

## Release boundary

Before publishing, complete [`../PUBLIC_RELEASE_CHECKLIST.md`](../PUBLIC_RELEASE_CHECKLIST.md)
for one fixed commit and artifact set. In particular, close the OSS license and
third-party rights decisions, run the controlled zero-skip lane, enable the
GitHub security gates, reproduce the package on each supported platform, and
obtain independent review. CI, hashes, an SBOM, or a signature alone do not
authorize release or customer delivery.
