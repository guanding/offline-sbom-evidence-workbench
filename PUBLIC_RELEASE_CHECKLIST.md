# Public source and artifact release checklist

## Current state

| Lane | Status |
| --- | --- |
| Public GitHub source repository | **ELIGIBLE** when the fixed clean commit passes current CI and the strict source-candidate gate |
| GitHub Release or signed tag | **BLOCKED / NOT OFFERED** |
| Wheel or sdist publication | **BLOCKED / NOT OFFERED** |
| Container or portable artifact | **NOT OFFERED** |
| Customer delivery or conformity evidence | **OUT OF SCOPE** |

Repository visibility and artifact distribution are separate decisions. Making
the source repository public does not approve a GitHub Release, wheel, sdist,
evidence pack, customer delivery, or CRA conclusion.

## Solo-maintainer record

Ding Guan (`@guanding`) is the copyright holder, repository owner, source
rights declarant, security contact, and conduct moderator. The project has no
second reviewer or alternate contact. Source-publication decisions are
therefore maintainer self-review and must not be described as independent or
four-eye approval.

## Source repository visibility gate

For the exact commit made public:

- [ ] the worktree is clean and `release/build_public_candidate.py --strict`
      reports `source_repository_publication_eligible: true`;
- [ ] current CI and security workflows pass from a clean clone;
- [ ] the Apache-2.0 `LICENSE`, `NOTICE`, package metadata, source rights
      record, and 45-file project-owned asset manifest agree;
- [ ] the explicit allowlist excludes vendored CycloneDX/SPDX specs, runtime,
      evidence, controlled PRO-03B inputs, customer data, local models, and secrets;
- [ ] the Git history and public Actions logs/artifacts contain no customer,
      credential, local-path, or internal-only material;
- [ ] no workflow can publish a Release, package, image, or evidence pack;
- [ ] GitHub private vulnerability reporting is enabled after visibility changes;
- [ ] README, SECURITY, and SUPPORT describe an unreleased source preview with
      no SLA and no conformity/customer-evidence claim.

A single CODEOWNER is valid for this project. Automated checks are technical
gates, not independent approval.

## Artifact distribution gate

Keep wheel, sdist, and GitHub Release lanes blocked until the exact proposed
bytes have:

- [ ] a complete direct/transitive license, notice, compatibility, and
      source-obligation review;
- [ ] confirmed exclusion or explicit redistribution approval for every
      vendored specification and other third-party input;
- [ ] the controlled zero-skip test lane and supported-platform reproduction;
- [ ] an exact manifest, hashes, SBOM, provenance/attestation, and signature;
- [ ] installation and offline-resource checks outside the source checkout;
- [ ] support, maintenance, rollback, and disclosure terms for the version;
- [ ] a recorded maintainer authorization naming the exact commit and hashes.

If an independent reviewer is unavailable, do not invent one. Record
`SOLE_MAINTAINER_SELF_REVIEW` and the resulting assurance limitation.

CI success, an SBOM, a hash, or a signature does not by itself authorize
artifact distribution or establish customer delivery, certification, or
conformity.
