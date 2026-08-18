"""Resolve source-checkout and installed-wheel data without host-specific paths.

Project-owned schemas, registries, and synthetic fixtures are installed below
``share/offline-sbom-evidence-workbench``.  Rights-restricted validation specs
are deliberately *not* package data: an installed wheel must receive them from
an operator-controlled BYO directory and fails closed when none is configured.
"""

from __future__ import annotations

import os
import stat
import sysconfig
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path, PurePosixPath


DIST_NAME = "offline-sbom-evidence-workbench"
DATA_ROOT_ENV = "SBOM_WORKBENCH_DATA_ROOT"
PROJECT_ROOT_ENV = "SBOM_WORKBENCH_PROJECT_ROOT"
VENDOR_SPECS_ROOT_ENV = "SBOM_WORKBENCH_VENDOR_SPECS_ROOT"
_SHARE_RELATIVE = Path("share") / DIST_NAME
_DATA_MARKERS = (
    PurePosixPath("schemas/synthetic-candidate.schema.json"),
    PurePosixPath("datasets/runtime_registry.json"),
    PurePosixPath("fixtures/synthetic_orion/release-a/release.json"),
)


class ResourceError(RuntimeError):
    """Raised when a required local resource closure is absent or unsafe."""


def _non_symlink_directory(path: Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise ResourceError(f"{label} is unavailable: {candidate}") from exc
    if candidate.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise ResourceError(f"{label} must be a non-symlink directory: {candidate}")
    return candidate.resolve(strict=True)


def _source_checkout_from_module() -> Path | None:
    package_directory = Path(__file__).resolve().parent
    candidate = package_directory.parents[1]
    expected_package = candidate / "src" / "sbom_workbench"
    try:
        is_checkout = (
            (candidate / "pyproject.toml").is_file()
            and expected_package.resolve(strict=True) == package_directory
        )
    except OSError:
        is_checkout = False
    return candidate if is_checkout else None


def source_checkout_root() -> Path | None:
    """Return an explicitly configured or verified source checkout, if any."""

    configured = os.environ.get(PROJECT_ROOT_ENV)
    if configured:
        root = _non_symlink_directory(Path(configured), "configured project root")
        if not (root / "pyproject.toml").is_file():
            raise ResourceError(
                f"{PROJECT_ROOT_ENV} does not identify an SBOM Workbench checkout"
            )
        return root
    return _source_checkout_from_module()


def _valid_data_root(candidate: Path) -> Path | None:
    try:
        root = _non_symlink_directory(candidate, "workbench data root")
    except ResourceError:
        return None
    if all((root / marker.as_posix()).is_file() for marker in _DATA_MARKERS):
        return root
    return None


def _distribution_data_root() -> Path | None:
    try:
        installed = distribution(DIST_NAME)
    except PackageNotFoundError:
        return None
    marker_suffix = PurePosixPath(
        "share",
        DIST_NAME,
        _DATA_MARKERS[0].as_posix(),
    ).as_posix()
    for entry in installed.files or ():
        if entry.as_posix().endswith(marker_suffix):
            marker = Path(installed.locate_file(entry)).resolve(strict=False)
            return _valid_data_root(marker.parents[1])
    return None


def data_root() -> Path:
    """Resolve the project-owned data closure for checkout or wheel installs."""

    configured = os.environ.get(DATA_ROOT_ENV)
    if configured:
        root = _valid_data_root(Path(configured))
        if root is None:
            raise ResourceError(
                f"{DATA_ROOT_ENV} is missing required schemas, datasets, or synthetic fixtures"
            )
        return root

    checkout = source_checkout_root()
    if checkout is not None:
        root = _valid_data_root(checkout)
        if root is not None:
            return root

    # ``uv pip install --target`` installs wheel data beside the package.  A
    # normal venv installs it below sysconfig's data prefix.  Distribution
    # metadata is the final location-independent fallback.
    package_parent = Path(__file__).resolve().parent.parent
    candidates = (
        package_parent / _SHARE_RELATIVE,
        Path(sysconfig.get_path("data")) / _SHARE_RELATIVE,
    )
    for candidate in candidates:
        root = _valid_data_root(candidate)
        if root is not None:
            return root
    root = _distribution_data_root()
    if root is not None:
        return root
    raise ResourceError(
        "installed workbench data closure is unavailable; reinstall the wheel or set "
        f"{DATA_ROOT_ENV} to an extracted project-owned data directory"
    )


def resource_path(relative_path: str) -> Path:
    """Return one safe regular file from the project-owned data closure."""

    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise ResourceError(f"unsafe workbench resource path: {relative_path}")
    root = data_root()
    candidate = root / relative.as_posix()
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        info = candidate.lstat()
    except (OSError, ValueError) as exc:
        raise ResourceError(f"workbench resource is unavailable: {relative_path}") from exc
    if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ResourceError(f"workbench resource is not a regular file: {relative_path}")
    return resolved


def optional_checkout_path(relative_path: str) -> Path | None:
    """Resolve a checkout-only operational artifact without inventing a cwd."""

    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise ResourceError(f"unsafe checkout-relative path: {relative_path}")
    root = source_checkout_root()
    if root is None:
        return None
    candidate = root / relative.as_posix()
    return candidate if candidate.is_file() and not candidate.is_symlink() else None


def vendor_specs_root(configured: Path | None = None) -> Path:
    """Resolve the rights-restricted offline spec closure or fail closed.

    The public wheel/sdist intentionally excludes ``vendor/specs``.  A source
    checkout may use its reviewed local copies; an installed artifact must set
    :data:`VENDOR_SPECS_ROOT_ENV` or pass an explicit directory.
    """

    selected: Path | None = configured
    if selected is None:
        environment_value = os.environ.get(VENDOR_SPECS_ROOT_ENV)
        if environment_value:
            selected = Path(environment_value)
    if selected is None:
        checkout = source_checkout_root()
        if checkout is not None:
            selected = checkout / "vendor" / "specs"
    if selected is None:
        raise ResourceError(
            "frozen CycloneDX/SPDX specs are not distributed in public artifacts; "
            f"provide a reviewed BYO directory via {VENDOR_SPECS_ROOT_ENV}"
        )
    return _non_symlink_directory(selected, "BYO frozen validation spec root")
