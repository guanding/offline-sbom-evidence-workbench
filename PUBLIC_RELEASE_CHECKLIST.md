# Public release checklist

**Current readiness: BLOCKED. Do not create a public repository or GitHub
Release from the current candidate.**

Copy this checklist into the release record for one fixed commit and exact
artifact set. Do not inherit checkmarks from an older build.

## Repository and governance

- [ ] GitHub remote ownership, visibility, branch protection, and required
      checks are approved.
- [ ] `CODEOWNERS` resolves to at least two active, independent reviewers for
      release-sensitive paths.
- [ ] Named security and conduct contacts, including alternates, are configured.
- [ ] `SECURITY.md`, `SUPPORT.md`, contribution terms, and response targets match
      the versions actually offered.
- [ ] Issue/PR templates were tested on the public repository.

## Rights

Standing decision: project source code, documentation, and the allowlisted
`schemas/`, `datasets/`, and `fixtures/synthetic_orion/` assets owned by Ding
Guan are licensed under Apache-2.0. The checkbox below verifies one fixed
release and `release/project_owned_assets.sha256`; it does not approve
referenced third-party objects, third-party material, or any other asset path.

- [ ] The exact release contains the official Apache-2.0 `LICENSE` and
      `Copyright 2026 Ding Guan` in `NOTICE`, and package/documentation metadata
      agrees.
- [ ] Direct and transitive dependency licenses, required notices, source-offer
      obligations, and compatibility were independently reviewed.
- [ ] Every vendored CycloneDX/SPDX artifact has explicit redistribution
      approval or is absent from the release bytes.
- [ ] Evidence, datasets, fixtures, manuals, images, reports, acquisition
      receipts, and model/runtime records each have an approved public status or
      are excluded.
- [ ] The rights reviewer approved the exact wheel/sdist hashes before any
      separate manual distribution operation; verification-only CI remains
      unable to upload those artifacts.
- [ ] `THIRD_PARTY_NOTICES.md` names the reviewer, date, scope, and exact bytes;
      no `NOT_APPROVED` or `AWAITING_NAMED_REVIEW` item remains.

## Repository and data hygiene

- [ ] A clean public clone contains no customer evidence, proprietary source,
      model secret, runtime state, credential, private key, personal data,
      machine-specific path, or internal-only planning material.
- [ ] An approved scanner checked the current tree and full Git history.
- [ ] Binaries, Office/PDF files, archives, generated reports, evidence packs,
      wheel/sdist contents, and metadata were inspected separately.
- [ ] The public artifact set is generated from an explicit allowlist.

## Build and security

- [ ] CI passes from a clean clone on the declared Python 3.12 lane.
- [ ] The public-source lane's explicit skip taxonomy is reviewed; the final
      controlled RC run supplies approved BYO specs, PRO-03B fixture, built
      artifacts, and loopback support, and has no unexplained or allowed skips.
- [ ] `uv.lock` is frozen and the exact `uv` version/tool identity is recorded.
- [ ] Wheel and sdist build reproducibly; the installed wheel works outside the
      source checkout and contains all required offline resources.
- [ ] Dependabot is active and dependency audit has no unresolved prohibited
      finding.
- [ ] CodeQL default setup or an advanced workflow with reviewed full action
      SHAs completed successfully.
- [ ] All Actions use verified full commit SHAs and least-privilege permissions.
- [ ] If an OCI artifact exists, a reviewed digest-pinned scanner reports zero
      unwaived critical/high findings or approved time-bounded exceptions.

## Version and artifacts

- [ ] Package metadata, module version, documentation, release notes, tag, and
      artifact filenames use one approved version.
- [ ] CHANGELOG/release notes describe security, compatibility, migration, and
      known limitations.
- [ ] Each artifact has a SHA-256, exact-set manifest, SPDX or CycloneDX SBOM,
      provenance/attestation, and verifiable signature.
- [ ] A separate reviewer reproduced installation and the documented synthetic
      demonstration from downloaded release artifacts.
- [ ] The signed annotated tag points to the reviewed commit, and the GitHub
      Release contains only reviewed artifact hashes.

## Approval

- [ ] Release owner: name, date, fixed commit.
- [ ] Rights reviewer: name, date, approved artifact hashes.
- [ ] Security/supply-chain reviewer: name, date, approved artifact hashes.
- [ ] Post-release verification and rollback/revocation owner are recorded.

CI success, an SBOM, a hash, a signature, or historical test evidence does not
by itself satisfy this checklist or establish customer delivery, certification,
or conformity.
