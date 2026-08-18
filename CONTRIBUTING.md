# Contributing

## Current contribution boundary

Project-owned content is licensed under Apache License 2.0. Unless explicitly
stated otherwise, contributions intentionally submitted for inclusion are
provided under Section 5 of that license. Contributors must have the right to
submit their work and must not submit customer, confidential, or unapproved
third-party material. This is a single-maintainer public-source project; no
response time or acceptance is promised.

## Development checks

Use a clean checkout and the locked environment:

```text
python -m venv .ci-tools
.ci-tools/bin/python -m pip install --require-hashes -r requirements-ci.lock
.ci-tools/bin/uv lock --check
.ci-tools/bin/uv sync --frozen
.ci-tools/bin/ruff check src tests scripts tools release
.ci-tools/bin/uv run --frozen python -m unittest discover -s tests
sh scripts/test_built_artifacts.sh
```

Packaging changes must also install the wheel into a clean environment outside
the source checkout and verify that required schemas and frozen validation
resources are present. These checks are engineering evidence only; they do not
establish release or customer-delivery approval.

## Pull request requirements

- Keep changes bounded; avoid unrelated formatting churn.
- Add or update tests for observable behavior.
- Use synthetic or explicitly redistributable fixtures.
- Never commit customer evidence, credentials, proprietary source, local model
  data, private runtime state, or machine-specific paths.
- Record source, version, cryptographic hash, license candidate, and
  redistribution decision for every copied or generated third-party asset.
- Treat `NOT_APPROVED` and `AWAITING_NAMED_REVIEW` as fail-closed states.
- Preserve the distinctions between engineering validation, release approval,
  customer evidence, and conformity assessment.

The PR template is the minimum evidence set. Ding Guan (`@guanding`) is the
sole reviewer. Reviews are maintainer self-review unless an external review is
explicitly recorded. Artifact distribution follows the separate blocked lane
in `RELEASE_PROCESS.md`.

## Commit and review expectations

Write focused commits with an imperative summary. Do not rewrite another
contributor's history. A CODEOWNER review routes responsibility and does not
claim independent rights, security, or artifact-release approval.
