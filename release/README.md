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

Verify the generated candidate before and after executing its tests. Keep the
test environment outside the candidate so environment creation cannot change
the exact file set:

```bash
python3 release/verify_public_candidate.py /tmp/sbom-workbench-public
python3 release/check_public_links.py /tmp/sbom-workbench-public
cd /tmp/sbom-workbench-public
sh scripts/test_public_source.sh
```

`scripts/test_public_source.sh` creates an offline environment outside the
candidate and verifies the public manifest before and after the run.
`release/run_public_tests.py` enforces the deliberately reduced public-source
test taxonomy. Build and test the explicit candidate as shown above.
