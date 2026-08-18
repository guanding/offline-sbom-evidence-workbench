# Release process

## Release state

Project-owned source code, documentation, and the allowlisted `schemas/`,
`datasets/`, and `fixtures/synthetic_orion/` assets are licensed under
Apache-2.0, Copyright 2026 Ding Guan, for the exact bytes in
`release/project_owned_assets.sha256`. Third-party facts, names, trademarks,
tools, models, sources, and artifacts referenced by the datasets are not
relicensed. Public release remains blocked because vendored specifications are
explicitly `NOT_APPROVED`, dependency/build/Action licenses still require named
review, other tracked evidence/assets remain excluded or pending, and CodeQL is
not enabled. Local wheel/sdist and installed-resource smoke tests pass for the
current candidate. The build backend and CI tools are pinned, and release
builds normalize wheel/sdist timestamps and sdist owner/group fields;
independent clean-environment reproducibility and supported-platform checks
remain required.

No automated publishing workflow is provided while those conditions remain.
A workflow artifact, local wheel, evidence pack, SBOM, signature, or green CI
run is a candidate only.

CI builds and installs wheel/sdist candidates for verification but has no step
that uploads them. Distribution requires a separate manual operation designed
and reviewed for one fixed commit and pre-approved exact artifact hashes.

## Roles

Assign named people for each release:

- **Release owner:** fixes the commit and exact artifact set.
- **Rights reviewer:** approves the project license, dependencies, vendored
  specifications, data, documents, images, fixtures, and notices.
- **Security/supply-chain reviewer:** independently reviews secret scans,
  vulnerabilities, build provenance, SBOMs, and signatures.

The rights reviewer and security/supply-chain reviewer must not both be
replaced by the release owner. CODEOWNERS routing alone is insufficient.

## Procedure

1. **Freeze scope.** Start from a clean protected branch, record the commit
   SHA, version, supported Python versions/platforms, and artifact allowlist.
2. **Close rights gates.** Verify the recorded Apache-2.0 grant and NOTICE are
   present in the exact release bytes. Approve `THIRD_PARTY_NOTICES.md`; remove
   every unapproved asset or vendored spec.
3. **Sanitize.** Scan the current tree, full Git history, binaries, archives,
   Office/PDF metadata, generated outputs, evidence, datasets, and wheel/sdist
   contents for secrets, personal/customer data, local paths, and internal-only
   material.
4. **Verify packages.** From a clean clone, reproduce the locked environment on
   the supported Python matrix. Build wheel and sdist, install the wheel outside
   the source checkout, and exercise required offline schemas/specifications.
   First review the public-source lane's explicit skip taxonomy; then run the
   controlled RC with approved BYO specs, PRO-03B fixture, built artifacts, and
   loopback support, requiring zero unexplained or allowed skips.
5. **Run security gates.** Complete dependency audit, CodeQL, approved
   full-history secret scanning, and artifact scanning. If an OCI image is
   introduced, add a reviewed digest-pinned container scanner.
6. **Create evidence.** Produce checksums, an exact-set manifest, SPDX or
   CycloneDX release SBOMs, provenance/attestations, and signatures for every
   released artifact.
7. **Independent review.** Both reviewers examine the fixed commit and final
   artifact hashes. Rebuilding after review invalidates that approval.
8. **Authorize distribution.** Only after the rights reviewer approves the
   exact distribution hashes, perform a separately reviewed manual upload for
   the fixed commit. Do not add or enable a repository-wide boolean bypass in
   the verification CI workflow.
9. **Publish.** Create a signed annotated tag and GitHub Release only after all
   items in `PUBLIC_RELEASE_CHECKLIST.md` are complete.
10. **Post-release.** Verify downloads, hashes, signatures, installation,
   documentation, and vulnerability-reporting access from a separate machine.
   Record the rollback or revocation path.

## Expected artifacts

At minimum, an approved release should contain a controlled source archive,
wheel, sdist, checksums, release notes, dependency notices, SBOMs, and
provenance. Evidence packs, datasets, manuals, screenshots, model/runtime
records, and vendored standards are excluded unless individually listed in the
approved allowlist with redistribution evidence.

GitHub-generated source snapshots must be evaluated separately from controlled
release archives because their byte set and timestamps may differ.

## CodeQL activation

`.github/codeql/codeql-config.yml` defines the intended analysis scope. No
advanced CodeQL workflow was added because a trustworthy full commit SHA for
`github/codeql-action` was not available in the offline authoring environment.
Before release, either enable GitHub CodeQL default setup and record a
successful analysis, or add an advanced workflow using a maintainer-verified
full action SHA. A mutable reference such as `@v3` is not acceptable.
