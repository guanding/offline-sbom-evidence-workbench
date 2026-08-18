# Public release builder

Build candidates only through the explicit allowlist:

```bash
python3 release/build_public_candidate.py --output /tmp/sbom-workbench-public
```

Use `--strict` for the formal release gate. It verifies the canonical
Apache-2.0 license, the Ding Guan copyright notice, package metadata,
the exact project-owned asset manifest, third-party rights status, and source
cleanliness. It refuses to build if an approved asset is added, removed, or
changed without renewing the exact-byte decision, and intentionally returns
non-zero while any other required release decision remains pending.

The builder does not establish copyright ownership, license compatibility,
customer-data clearance, conformity, certification, or release approval.
