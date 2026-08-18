# Security policy

## Current support status

This public repository is an unreleased source preview. No GitHub Release,
wheel, sdist, container image, portable bundle, or supported product version is
currently offered. Security reports are handled on a best-effort basis; no
response or remediation SLA is promised.

| Scope | Status |
| --- | --- |
| Public source on the default branch | Unreleased preview; best effort |
| Tags, GitHub Releases, packages, images, bundles | Not offered |

## Reporting a suspected vulnerability

Use GitHub's **Report a vulnerability** link on the repository Security page.
The report is private to the repository owner. Do not open a public issue with
vulnerability details.

Ding Guan (`@guanding`) is the primary and only security contact. This is a
single-maintainer project: there is no alternate contact, independent security
reviewer, or separate escalation path. If private vulnerability reporting is
temporarily unavailable, open a public issue containing no sensitive details
and ask the maintainer to establish a private channel.

Include only the minimum necessary information:

- affected commit or source path;
- reproducible steps using synthetic or public data where possible;
- impact and required preconditions;
- a proposed disclosure date;
- whether customer, personal, credential, or embargoed data is involved.

Never submit customer data or SBOMs, proprietary source, credentials, private
keys, production logs, runtime databases, or embargoed vulnerability details
through a public channel.

## Maintainer handling

The sole maintainer will acknowledge and assess reports as availability allows,
reproduce against a fixed commit with synthetic or authorized data, record the
affected scope and disclosure decision, and rotate any exposed credential.
Advisories and fixes are self-reviewed unless the maintainer explicitly records
an external review; no independent review is implied.

## Scope boundary

A tool result, passing CI job, generated SBOM, signature, or vulnerability
report does not establish CRA conformity, certification, customer acceptance,
legal advice, or permission to disclose customer evidence.
