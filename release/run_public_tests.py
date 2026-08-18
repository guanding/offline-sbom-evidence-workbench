#!/usr/bin/env python3
"""Run the public-source suite and enforce its deliberate skip taxonomy."""

from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import sys
import unittest


EXPECTED_SKIP_COUNTS = {
    "external controlled PRO-03B fixture is unavailable; set "
    "SBOM_WORKBENCH_PRO03B_TEMPLATE": 6,
    "set SBOM_WORKBENCH_BUILT_WHEEL to test an already-built wheel": 1,
    "set SBOM_WORKBENCH_BUILT_SDIST to test an already-built sdist": 1,
    "BYO CycloneDX/SPDX validation specs are unavailable in the public source set": 11,
    "historical acquisition evidence is intentionally absent from the public source set": 1,
}
EXPECTED_TEST_COUNT = 323
ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    # The invoking interpreter may belong to an editable developer checkout.
    # Put the candidate's src-layout ahead of site-packages and verify the
    # resolved package before collecting tests, otherwise a green run could
    # accidentally exercise different bytes.
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
    os.chdir(ROOT)
    import sbom_workbench

    package_file = Path(sbom_workbench.__file__).resolve()
    try:
        package_file.relative_to(ROOT)
    except ValueError:
        print(
            f"Refusing to test external package bytes: {package_file}",
            file=sys.stderr,
        )
        return 3
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    if result.testsRun != EXPECTED_TEST_COUNT:
        print(
            "Public-source total test count drifted: "
            f"expected={EXPECTED_TEST_COUNT}, actual={result.testsRun}.",
            file=sys.stderr,
        )
        return 2
    actual = Counter(str(reason) for _test, reason in result.skipped)
    expected = Counter(EXPECTED_SKIP_COUNTS)
    if actual != expected:
        print("Public-source skip taxonomy drifted.", file=sys.stderr)
        print(f"expected={dict(sorted(expected.items()))}", file=sys.stderr)
        print(f"actual={dict(sorted(actual.items()))}", file=sys.stderr)
        return 2
    print(
        f"Public-source boundary verified: {result.testsRun} tests, "
        f"{sum(actual.values())} deliberate skips."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
