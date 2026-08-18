# Public release builder

Build candidates only through the explicit allowlist:

```bash
python3 release/build_public_candidate.py --output /tmp/sbom-workbench-public
```

Use `--strict` for the public-source visibility gate. It verifies the
canonical Apache-2.0 license, the Ding Guan copyright notice, package metadata,
the exact project-owned asset manifest, source rights, and source cleanliness.
It refuses to build if an approved asset is added, removed, or changed without
renewing the exact-byte decision.

The builder does not approve a GitHub Release, wheel, sdist, copyright
ownership, dependency license compatibility, customer-data clearance,
conformity, certification, or artifact distribution.
