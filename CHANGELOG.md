# Changelog

All notable changes to this project are documented here. The project has not
yet published a stable public release.

## 0.5.0-rc.1 - Unreleased

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

### Changed

- Removed machine-specific paths from runtime and EUVD self-test tooling.
- Declared the current support boundary as CPython 3.12 on POSIX.
- Aligned display and package versions at `0.5.0-rc.1` / `0.5.0rc1`.

### Security and compatibility notes

- Public packages exclude `vendor/specs` and require reviewed BYO inputs for
  specification-backed validation.
- Windows is unsupported; Linux full-release validation is incomplete, and
  some network-denial tests remain macOS-specific.
- The allowlisted schemas, datasets, and synthetic Orion fixtures are approved
  project-owned material. Other governed assets remain excluded or subject to
  named rights review.
- Project-owned material is licensed under Apache-2.0. Dependency and tool
  rights, release governance, and independent validation remain open, so this
  candidate is not yet approved for public release or customer delivery.
