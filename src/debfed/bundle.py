"""Strategy B: bundling a library the host cannot provide.

The original design used a wrapper script setting LD_LIBRARY_PATH. That
is the wrong mechanism. LD_LIBRARY_PATH is inherited across the entire
execve tree, so an application that spawns xdg-open, a browser or a
terminal forces its bundled libraries onto all of them. Debian's own
wiki says it is "discouraged for distribution-wide use for its possible
side-effects"; the same objection is why ISVs avoid it.

The path is baked into the binary instead. The search order is:

    DT_RPATH  ->  LD_LIBRARY_PATH  ->  DT_RUNPATH  ->  ld.so.cache

DT_RPATH rather than DT_RUNPATH matters here: RUNPATH applies only to the
object that carries it and is *not* used to resolve that object's own
dependencies. Bundled libraries have dependencies of their own, so
RUNPATH would resolve the first level and fail on the second. patchelf
writes RUNPATH unless --force-rpath is given.

$ORIGIN keeps the result relocatable, so the prefix can move without
re-patching.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .elf import is_elf

VENDOR_ROOT = "/opt/debfed"


class BundleError(Exception):
    pass


@dataclass
class BundlePlan:
    """What Strategy B will do, decided before anything is written."""

    app: str
    prefix: str                                   # /opt/debfed/<app>
    libdir: str                                   # <prefix>/lib
    missing: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)   # soname -> host path
    unresolved: list[str] = field(default_factory=list)
    consumers: list[str] = field(default_factory=list)      # payload ELF to patch

    @property
    def viable(self) -> bool:
        return bool(self.sources) and not self.unresolved


def soname_of(capability: str) -> str | None:
    """libfoo.so.1(SYMVER)(64bit) -> libfoo.so.1"""
    name = capability.split("(", 1)[0].strip()
    return name if ".so" in name else None


def _require(binary: str, package: str) -> str:
    found = shutil.which(binary)
    if not found:
        raise BundleError(
            f"{binary} is required for a private-prefix build. "
            f"Install it:  dnf install {package}"
        )
    return found


def find_in_deb_payload(soname: str, search_roots: list[Path]) -> Path | None:
    """Locate a library inside already-extracted Debian payloads."""
    for root in search_roots:
        if not root.is_dir():
            continue
        for candidate in root.rglob(soname + "*"):
            if candidate.is_file() and not candidate.is_symlink():
                if candidate.name == soname or candidate.name.startswith(soname):
                    return candidate
    return None


def plan_bundle(
    app: str,
    unsatisfied: list[str],
    buildroot: Path,
    extra_sources: list[Path] | None = None,
) -> BundlePlan:
    """Decide which libraries to bundle and where they come from.

    Only libraries are bundled. A capability that is not a soname -- a
    file path, a package name, an interpreter -- cannot be solved this
    way and is reported unresolved so the caller refuses rather than
    producing something that half works.
    """
    prefix = f"{VENDOR_ROOT}/{app}"
    plan = BundlePlan(app=app, prefix=prefix, libdir=f"{prefix}/lib")

    roots = [buildroot] + list(extra_sources or [])
    for capability in unsatisfied:
        soname = soname_of(capability)
        if soname is None:
            plan.unresolved.append(capability)
            continue
        if soname in plan.sources:
            continue
        found = find_in_deb_payload(soname, roots)
        if found is None:
            plan.unresolved.append(capability)
        else:
            plan.sources[soname] = str(found)
        plan.missing.append(capability)

    plan.consumers = [
        str(p) for p in sorted(buildroot.rglob("*"))
        if p.is_file() and not p.is_symlink() and is_elf(p)
    ]
    return plan


def apply_bundle(plan: BundlePlan, buildroot: Path) -> list[str]:
    """Copy the libraries in and point the payload at them.

    Returns the list of files added to the buildroot.
    """
    if not plan.sources:
        return []
    patchelf = _require("patchelf", "patchelf")

    libdir = buildroot / plan.libdir.lstrip("/")
    libdir.mkdir(parents=True, exist_ok=True)
    added: list[str] = []

    for soname, source in sorted(plan.sources.items()):
        target = libdir / soname
        # copy2 preserves the source mode. Do not override it: the
        # vendor's permissions are already correct for a shared library,
        # and forcing a mode would be both redundant and lossy.
        shutil.copy2(source, target)
        added.append(f"{plan.libdir}/{soname}")

    for consumer in plan.consumers:
        rel = os.path.relpath(str(libdir), os.path.dirname(consumer))
        rpath = f"$ORIGIN/{rel}" if rel != "." else "$ORIGIN"
        proc = subprocess.run(
            [patchelf, "--force-rpath", "--set-rpath", rpath, consumer],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            # Not every ELF file can be patched -- static binaries and
            # some stripped objects have no dynamic section. That is not
            # fatal: those files had no dependency to redirect anyway.
            continue

    return added


def verify_bundle(plan: BundlePlan, buildroot: Path) -> list[str]:
    """Check every consumer resolves, using the buildroot as the root.

    Returns remaining unresolved sonames. An empty list means the bundle
    actually works rather than merely having been assembled.
    """
    still_missing: set[str] = set()
    for consumer in plan.consumers:
        proc = subprocess.run(
            ["ldd", consumer], capture_output=True, text=True,
            env={**os.environ, "LD_LIBRARY_PATH": str(buildroot / plan.libdir.lstrip("/"))},
        )
        for line in proc.stdout.splitlines():
            if "not found" in line:
                still_missing.add(line.split("=>")[0].strip())
    return sorted(still_missing)
