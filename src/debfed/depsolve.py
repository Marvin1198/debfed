"""Dependency resolution.

The central insight of debfed: do not translate Debian's `Depends:` field.
Run rpm's own ELF dependency generator over the relocated payload and let
it emit capabilities in Fedora's native syntax:

    libgtk-3.so.0()(64bit)
    libc.so.6(GLIBC_2.38)(64bit)
    rtld(GNU_HASH)

Sonames are defined upstream, so they are identical across distributions.
Package names are not. Resolving on sonames is the reliable path; the
mapping database only covers the residue (fonts, icon themes, helper
binaries invoked at runtime).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

RPMDEPS_CANDIDATES = (
    "/usr/lib/rpm/rpmdeps",
    "/usr/lib64/rpm/rpmdeps",
    "rpmdeps",
)

GLIBC_RE = re.compile(r"GLIBC_(\d+)\.(\d+)(?:\.(\d+))?")

# Capabilities rpm generates that are always satisfied by any Fedora host.
ALWAYS_SATISFIED = frozenset({"rtld(GNU_HASH)"})

TOOLKIT_SONAMES = (
    "libgtk-", "libgdk-", "libglib-", "libgobject-", "libgio-",
    "libQt5", "libQt6", "libEGL", "libGL", "libGLX", "libGLdispatch",
    "libnss3", "libnssutil3", "libsmime3", "libwayland-", "libX11",
    "libsystemd", "libdbus-1",
)


class ResolveError(Exception):
    pass


@lru_cache(maxsize=1)
def _rpmdeps_bin() -> str:
    for candidate in RPMDEPS_CANDIDATES:
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        elif shutil.which(candidate):
            return candidate
    raise ResolveError(
        "rpmdeps not found. Install the rpm-build package:  dnf install rpm-build"
    )


@lru_cache(maxsize=1)
def _dnf_bin() -> str:
    for candidate in ("dnf5", "dnf"):
        if shutil.which(candidate):
            return candidate
    raise ResolveError("dnf not found")


def _payload_files(buildroot: Path) -> list[str]:
    return [
        str(p)
        for p in sorted(buildroot.rglob("*"))
        if p.is_file() and not p.is_symlink()
    ]


def _run_rpmdeps(buildroot: Path, flag: str) -> set[str]:
    files = _payload_files(buildroot)
    if not files:
        return set()
    caps: set[str] = set()
    # argv limits: chunk the file list
    for i in range(0, len(files), 400):
        proc = subprocess.run(
            [_rpmdeps_bin(), flag, *files[i : i + 400]],
            capture_output=True,
            text=True,
        )
        caps.update(line.strip() for line in proc.stdout.splitlines() if line.strip())
    return caps


def scan_requires(buildroot: Path) -> list[str]:
    """Capabilities the payload needs, in Fedora syntax."""
    return sorted(_run_rpmdeps(buildroot, "--requires"))


def scan_provides(buildroot: Path) -> list[str]:
    """Capabilities the payload would advertise. Mostly a leak hazard."""
    return sorted(_run_rpmdeps(buildroot, "--provides"))


# ------------------------------------------------------------ dnf queries


def _repoquery(cap: str) -> list[str]:
    proc = subprocess.run(
        [
            _dnf_bin(), "repoquery",
            "--quiet",
            "--qf", "%{name}",
            "--whatprovides", cap,
        ],
        capture_output=True,
        text=True,
    )
    seen: list[str] = []
    for line in proc.stdout.splitlines():
        name = line.strip()
        if name and name not in seen:
            seen.append(name)
    return seen


@dataclass
class Resolution:
    requires: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    satisfied: dict[str, list[str]] = field(default_factory=dict)
    unsatisfied: list[str] = field(default_factory=list)
    rpm_requires: list[str] = field(default_factory=list)
    checked: bool = True

    @property
    def fedora_packages(self) -> list[str]:
        """Distinct Fedora packages that satisfy the payload."""
        out: set[str] = set()
        for owners in self.satisfied.values():
            if owners:
                out.add(owners[0])
        return sorted(out)

    @property
    def missing_sonames(self) -> list[str]:
        return [c for c in self.unsatisfied if ".so" in c]

    @property
    def needs_newer_glibc(self) -> str | None:
        """Highest GLIBC_ symbol version the host could not satisfy."""
        worst: tuple[int, ...] | None = None
        worst_cap = None
        for cap in self.unsatisfied:
            m = GLIBC_RE.search(cap)
            if m and cap.startswith("libc.so"):
                ver = tuple(int(x) for x in m.groups() if x is not None)
                if worst is None or ver > worst:
                    worst, worst_cap = ver, cap
        return worst_cap

    @property
    def missing_toolkit(self) -> list[str]:
        return [
            c
            for c in self.unsatisfied
            if any(c.startswith(t) for t in TOOLKIT_SONAMES)
        ]


def resolve(buildroot: Path, jobs: int = 8, offline: bool = False) -> Resolution:
    """Scan the payload and check every requirement against Fedora."""
    res = Resolution()
    res.requires = scan_requires(buildroot)
    res.provides = scan_provides(buildroot)

    to_check = [c for c in res.requires if c not in ALWAYS_SATISFIED]
    res.rpm_requires = res.requires

    if offline:
        res.checked = False
        return res

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        owners = list(pool.map(_repoquery, to_check))

    for cap, found in zip(to_check, owners, strict=True):
        if found:
            res.satisfied[cap] = found
        else:
            res.unsatisfied.append(cap)
    return res
