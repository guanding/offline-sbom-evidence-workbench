# Security policy

## Current support status

This repository contains an Apache-2.0-licensed public-source candidate. It has
not yet completed the independent rights and security gates for an approved
public release, and no public version is currently supported.

| Version | Public security support |
| --- | --- |
| All current commits and local candidates | Not yet offered |

Publishing this file does not itself enable GitHub private vulnerability
reporting or create a support commitment.

## Reporting a suspected vulnerability

Do not open a public issue for a suspected vulnerability. After the repository
owner provisions a GitHub remote, use GitHub private vulnerability reporting.
If that feature is unavailable, contact the repository owner through the
organization's established private channel and ask for a security intake path
without including sensitive details in the first message.

Before public launch, a named monitored security contact and an alternate
contact must be recorded in the repository settings and release record. Until
that is done, public release remains blocked.

Include only the minimum necessary information:

- affected commit, version, artifact SHA-256, or execution lane;
- reproducible steps using synthetic data where possible;
- impact and required preconditions;
- a proposed disclosure date;
- whether customer, personal, credential, model, or embargoed data is involved.

Never submit customer SBOMs, proprietary source trees, model credentials,
runtime registries, private keys, production logs, or embargoed vulnerability
details through a public issue.

## Maintainer handling

Maintainers must:

1. acknowledge receipt through the private channel;
2. restrict evidence to the minimum named response team;
3. reproduce against a fixed commit and synthetic or authorized evidence;
4. record severity, affected versions, mitigation, and disclosure decision;
5. obtain independent review before publishing an advisory or release;
6. rotate or revoke any credential that may have been disclosed.

Response-time targets must be approved and published before a supported public
version is declared. Until then, no response SLA is promised.

## Scope boundary

A tool result, passing CI job, generated SBOM, evidence pack, signature, or
vulnerability report does not establish CRA conformity, certification,
customer acceptance, or permission to disclose customer evidence.
