## Summary

Describe the problem, the bounded change, and the observable outcome.

## Verification

- [ ] `ruff check src tests scripts tools release`
- [ ] `uv run --frozen python -m unittest discover -s tests`
- [ ] Wheel and sdist were built, and the wheel was smoke-tested outside the source checkout when packaging changed.
- [ ] Offline behavior and fail-closed evidence handling were checked when relevant.

## Rights, data, and security

- [ ] No customer data, credentials, proprietary source, model secrets, local runtime data, or machine-specific paths were added.
- [ ] New dependencies and copied/generated assets have source, version, hash, license, and redistribution status recorded.
- [ ] No `NOT_APPROVED` or `AWAITING_NAMED_REVIEW` material is presented as releasable.
- [ ] Security-sensitive changes include a threat/abuse-case note and regression coverage.

## Release boundary

- [ ] I understand that CI success is not public-release, customer-delivery, or conformity approval.
- [ ] If this changes a release artifact, the fixed commit and exact artifact set will receive independent review under `RELEASE_PROCESS.md`.
