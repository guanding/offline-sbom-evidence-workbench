# Changelog

All notable changes to this project are documented here. The project has not
yet published a stable public release.

## 0.6.0-rc.1 - Unreleased

### Added

- Install-time resource discovery for project-owned schemas, datasets, and
  synthetic fixtures.
- Explicit BYO configuration and fail-closed handling for rights-restricted
  CycloneDX/SPDX specification copies.
- Wheel/sdist build and installed-artifact smoke tests.
- GitHub CI, supply-chain inventory, governance, security, and release-gate
  documents.
- Explicit public-source allowlist with an exact SHA-256 manifest.
- Apache License 2.0 project licensing and the Ding Guan copyright notice.
- Recorded Ding Guan ownership and Apache-2.0 coverage for 45 exact allowlisted
  `schemas/`, `datasets/`, and `fixtures/synthetic_orion/` release-asset files,
  with a fail-closed SHA-256 manifest.
- Deterministic source-declaration population for Gradle, Bazel,
  Ruby/Bundler, SwiftPM, NuGet Central Package Management, and ESP-IDF, in
  addition to the previously supported ecosystems.
- Hash-anchored acquisition-receipt and file-by-file source-tree binding for
  governed source-only scans.
- A local graphical source-scan workflow for choosing files or a directory and
  downloading CycloneDX JSON, SPDX JSON, Syft JSON, and a hash-binding scan
  receipt.
- Bounded browser intake, single-worker local scan jobs, server-owned temporary
  storage, per-download hash verification, and fail-closed privacy projection.
- Generation-only startup without a registered evidence directory; the prior
  hash-bound evidence viewer remains available as a secondary tab.
- Static UI security/accessibility contracts and end-to-end loopback tests for
  upload, scan, download, and cleanup.

### Changed

- Upgraded the one-way EUVD handoff receipt to schema `1.1`, binding the
  CycloneDX bytes to a periodic component-rescan candidate purpose.
- Explicitly prohibit automatic vulnerability confirmation and CRA Article 14
  decisions in that handoff; product-version applicability remains a manual
  review boundary.
- Removed machine-specific paths from runtime and EUVD self-test tooling.
- Declared the current support boundary as CPython 3.12 on POSIX.
- Aligned display and package versions at `0.6.0-rc.1` / `0.6.0rc1`.
- Treat a path-only or `file` scanner root as `HOLD_SBOM_ROOT_IDENTITY` instead
  of allowing a declared product name to repair the scanner's product identity.
- Updated the public-source test-count drift gate to 383 tests and made the
  internal-observation exclusion test valid in both developer and allowlisted
  public-candidate trees.
- Added an isolated public-test wrapper that keeps `uv` metadata outside the
  candidate and re-verifies its exact-set manifest before and after testing.

### Security and compatibility notes

- Public packages exclude `vendor/specs` and require reviewed BYO inputs for
  specification-backed validation.
- Browser selection preserves file bytes and relative paths only; symlink and
  hard-link identity, ownership, and executable bits are outside this lane.
- Source-derived results remain single-face candidates. Coverage or component
  population HOLD states block release-quality handoff even when JSON syntax
  and exact-set bindings validate.
- Windows is unsupported; Linux full-release validation is incomplete, and
  some network-denial tests remain macOS-specific.
- The allowlisted schemas, datasets, and synthetic Orion fixtures are approved
  project-owned material. Other governed assets remain excluded or subject to
  named rights review.
- Project-owned material is licensed under Apache-2.0. Dependency and tool
  rights, release governance, and independent validation remain open, so this
  candidate is not yet approved for public release or customer delivery.
