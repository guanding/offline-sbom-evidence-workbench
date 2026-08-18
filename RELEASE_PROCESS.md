# Release process

## Two independent lanes

### Lane A — public source repository

The Apache-2.0 project source and the exact project-owned assets listed in
`release/project_owned_assets.sha256` may be made publicly visible from a
fixed clean commit after the strict source-candidate gate and current CI pass.
This lane publishes Git source only. It does not publish or approve a GitHub
Release, wheel, sdist, evidence pack, customer deliverable, or conformity
evidence.

### Lane B — versioned artifacts

This lane is currently **BLOCKED / NOT OFFERED**. CI may build and install
wheel/sdist candidates for verification, but it must not upload them. Artifact
rights, provenance, signatures, supported-platform tests, support terms, and
exact hashes require a separate decision.

## Current roles and assurance

Ding Guan (`@guanding`) is the sole maintainer, copyright holder, source
rights declarant, security contact, and conduct moderator. There is no alternate
or independent reviewer. Source publication is explicitly recorded as
`SOLE_MAINTAINER_SELF_REVIEW`; CODEOWNERS and CI do not turn it into
independent approval.

Independent review may be requested for a future artifact, but it is not a
condition imposed on public source visibility and must never be fabricated.

## Source-publication procedure

1. Freeze a clean commit and confirm the explicit public allowlist and the
   45-file project-owned asset manifest.
2. Run the strict candidate builder; verify the exact-set manifest and source
   visibility status.
3. Scan the clean tree and its short public history for secrets, customer data,
   local paths, private runtime state, vendored specs, and excluded evidence.
4. Run the current CI/security workflows. They may build wheel/sdist candidates
   for tests but must not upload them.
5. Confirm README, LICENSE, NOTICE, package metadata, THIRD_PARTY_NOTICES,
   SECURITY, SUPPORT, and contribution terms agree with the source-only boundary.
6. Change repository visibility to public, enable private vulnerability
   reporting and CodeQL default setup, then verify the public clone and checks.

## Future artifact procedure

Before any tag, GitHub Release, wheel, or sdist:

1. freeze the exact commit, platform matrix, and artifact allowlist;
2. review every direct/transitive dependency and build input for authoritative
   licenses, notices, compatibility, and source obligations;
3. keep vendored CycloneDX/SPDX specifications excluded unless explicit
   redistribution rights are documented;
4. reproduce the controlled zero-skip lane, build/install tests, and supported
   platform checks;
5. generate exact manifests, hashes, SBOMs, provenance/attestations, and
   signatures;
6. record support, rollback, revocation, and disclosure terms;
7. authorize only the named hashes, with the review model honestly labeled.

Rebuilding after authorization invalidates the artifact decision.
GitHub-generated source snapshots are not controlled artifact releases.

## CodeQL

The repository contains the intended CodeQL scope configuration. Enable GitHub
CodeQL default setup immediately after the repository becomes public, or later
add an advanced workflow pinned to a maintainer-verified full action SHA.
