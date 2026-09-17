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

from .elf import find_system_library, has_version_definitions, partition_by_arch

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
def host_glibc_version() -> tuple[int, ...] | None:
    """The running host's glibc version, as a comparable tuple."""
    try:
        raw = os.confstr("CS_GNU_LIBC_VERSION")
    except (ValueError, OSError):
        return None
    if not raw:
        return None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", raw)
    if not m:
        return None
    return tuple(int(x) for x in m.groups() if x is not None)


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


def _payload_files(buildroot: Path, arch: str = "x86_64") -> list[str]:
    """Files to hand the dependency generator, for this architecture only.

    Vendor packages routinely bundle helper binaries for other machines.
    Scanning those yields requirements no host of this architecture can
    satisfy -- ld-linux-aarch64.so.1 and friends -- which look like
    missing dependencies instead of files for a different CPU.
    """
    all_files = [
        p for p in sorted(buildroot.rglob("*"))
        if p.is_file() and not p.is_symlink()
    ]
    ours, foreign = partition_by_arch(all_files, arch)
    _FOREIGN_CACHE.clear()
    _FOREIGN_CACHE.update({k: [str(p) for p in v] for k, v in foreign.items()})
    return [str(p) for p in ours]


# Populated by _payload_files so callers can report what was skipped.
_FOREIGN_CACHE: dict[str, list[str]] = {}


def foreign_objects() -> dict[str, list[str]]:
    """Binaries for other architectures seen during the last scan."""
    return dict(_FOREIGN_CACHE)


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


USRMERGE_PREFIXES = ("/bin/", "/sbin/", "/lib/", "/lib64/")


def capability_variants(cap: str) -> list[str]:
    """Every spelling of a capability worth querying, most likely first.

    Fedora is usr-merged: /bin is a symlink to /usr/bin and rpm records
    most file provides under the real path, so /bin/bash must be looked
    up as /usr/bin/bash.

    But the rewrite is not universally correct. /usr/bin/sh is itself a
    symlink to bash, and rpm does not record symlinked paths as file
    provides -- Fedora instead carries an explicit `Provides: /bin/sh` on
    bash. Rewriting that one makes it unsatisfiable when the original
    would have resolved.

    Rather than guess which convention applies to a given path, try both
    and treat the capability as satisfied if either resolves.
    """
    variants = [cap]
    for prefix in USRMERGE_PREFIXES:
        if cap.startswith(prefix):
            variants.append("/usr" + cap)
            break
    else:
        for prefix in USRMERGE_PREFIXES:
            usr_form = "/usr" + prefix
            if cap.startswith(usr_form):
                variants.append(cap[len("/usr"):])
                break
    return variants


def normalise_capability(cap: str) -> str:
    """The usr-merged spelling of a capability. See capability_variants."""
    for prefix in USRMERGE_PREFIXES:
        if cap.startswith(prefix):
            return "/usr" + cap
    return cap


def _repoquery_one(spec: str) -> list[str]:
    proc = subprocess.run(
        [
            _dnf_bin(), "repoquery",
            "--quiet",
            # The trailing newline is essential: without it dnf writes every
            # matching package name onto one line, and two providers become
            # a single nonexistent package called "libcurllibcurl-minimal".
            "--qf", "%{name}\n",
            "--whatprovides", spec,
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


def _repoquery(cap: str) -> list[str]:
    """Resolve a capability, trying each valid spelling of it."""
    for spec in capability_variants(cap):
        found = _repoquery_one(spec)
        if found:
            return found
    return []


def max_required_glibc(requires: list[str]) -> tuple[int, ...] | None:
    """Highest GLIBC_ symbol version the payload demands, for THIS arch.

    Derived from the payload alone -- no repository access. Version skew
    is a property of the binaries and the running host, so making the
    check depend on dnf meant --offline silently accepted packages that
    could never run. Only 64-bit x86 requirements count; other
    architectures have their own, lower, symbol namespaces.
    """
    worst: tuple[int, ...] | None = None
    for cap in requires:
        if not cap.startswith(("libc.so.6", "libm.so.6", "libpthread.so.0",
                               "libdl.so.2", "librt.so.1")):
            continue
        if "(64bit)" not in cap:
            continue
        m = GLIBC_RE.search(cap)
        if not m:
            continue
        ver = tuple(int(x) for x in m.groups() if x is not None)
        if worst is None or ver > worst:
            worst = ver
    return worst


@dataclass
class Resolution:
    requires: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    satisfied: dict[str, list[str]] = field(default_factory=dict)
    unsatisfied: list[str] = field(default_factory=list)
    rpm_requires: list[str] = field(default_factory=list)
    checked: bool = True
    self_satisfied: list[str] = field(default_factory=list)
    foreign: dict[str, list[str]] = field(default_factory=dict)

    @property
    def fedora_packages(self) -> list[str]:
        """Distinct Fedora packages that satisfy the payload."""
        out: set[str] = set()
        for owners in self.satisfied.values():
            if owners:
                out.add(owners[0])
        return sorted(out)

    @property
    def symbol_version_only(self) -> list[str]:
        """Capabilities missing ONLY a symbol version, not the library.

        Some distributions add their own symbol versions to a library
        whose ABI is otherwise unchanged. Debian's libcurl is the
        canonical case: upstream curl exports unversioned symbols, and
        Debian added CURL_OPENSSL_3/4 during its libcurl3->4 transition.
        Fedora ships the upstream style, so a Debian binary asks for
        CURL_OPENSSL_4 from a library that is fully ABI-compatible but
        does not carry that label.

        These are reported separately because they are a naming artifact
        rather than a real incompatibility -- bundling resolves them, but
        the application would very likely have run either way.
        """
        satisfied_sonames = {
            cap.split("(", 1)[0] for cap in self.satisfied if ".so" in cap
        }
        out = []
        for cap in self.unsatisfied:
            base = cap.split("(", 1)[0]
            if ".so" not in base:
                continue
            # the bare soname resolves; only the versioned form does not
            if base in satisfied_sonames or f"{base}()(64bit)" in self.satisfied:
                out.append(cap)
        return out

    def _classify_version_miss(self, cap: str) -> str:
        """'cosmetic' | 'real' | 'unknown' for a symbol-version-only miss.

        glibc's dl-version.c: when the provider defines no symbol
        versions at all, a missing version is graceful degradation --
        a "no version information available" warning, and the program
        runs. When the provider DOES define versions but not the
        required one, the load fails.
        """
        soname = cap.split("(", 1)[0]
        lib = find_system_library(soname)
        if lib is None:
            return "unknown"
        versioned = has_version_definitions(lib)
        if versioned is None:
            return "unknown"
        return "real" if versioned else "cosmetic"

    @property
    def cosmetic_version_misses(self) -> list[str]:
        """Version misses the dynamic linker will only warn about.

        These do not need bundling. Sending them to a private prefix
        drags a distribution's whole dependency chain along to satisfy a
        label the linker does not enforce.
        """
        return [c for c in self.symbol_version_only
                if self._classify_version_miss(c) == "cosmetic"]

    @property
    def blocking_unsatisfied(self) -> list[str]:
        """Unsatisfied capabilities that genuinely prevent the app running."""
        cosmetic = set(self.cosmetic_version_misses)
        return [c for c in self.unsatisfied if c not in cosmetic]

    @property
    def missing_sonames(self) -> list[str]:
        return [c for c in self.unsatisfied if ".so" in c]

    @property
    def glibc_skew(self) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
        """(required, host) when the payload needs a newer glibc, else None.

        Independent of dnf: a binary requiring GLIBC_2.43 cannot run on a
        host with 2.39 regardless of what any repository contains.
        """
        host = host_glibc_version()
        required = max_required_glibc(self.requires)
        if host is None or required is None or required <= host:
            return None
        return required, host

    @property
    def needs_newer_glibc(self) -> str | None:
        """A GLIBC_ symbol genuinely newer than the host's glibc, if any.

        An unsatisfied libc symbol is NOT evidence of version skew. On
        x86_64 the glibc symbol namespace starts at GLIBC_2.2.5, so
        GLIBC_2.2 and GLIBC_2.2.4 never exist there and are unsatisfiable
        while being far older than any current glibc. They come from
        binaries built for other architectures, where the namespace
        starts lower.

        Only a version strictly greater than the host's is real skew.
        Treating any unsatisfied libc symbol as skew refuses working
        packages outright.
        """
        host = host_glibc_version()
        if host is None:
            return None
        worst: tuple[int, ...] | None = None
        worst_cap = None
        for cap in self.unsatisfied:
            if not cap.startswith("libc.so"):
                continue
            m = GLIBC_RE.search(cap)
            if not m:
                continue
            ver = tuple(int(x) for x in m.groups() if x is not None)
            if ver <= host:
                continue          # older than the host: not skew
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
    res.foreign = foreign_objects()

    # A package satisfies its own bundled libraries. rpm resolves these
    # internally at install time, so querying dnf for libffmpeg.so -- which
    # ships inside the payload -- reports a missing dependency that does
    # not exist.
    self_provided = set(res.provides)
    res.self_satisfied = sorted(set(res.requires) & self_provided)

    to_check = [
        c for c in res.requires
        if c not in ALWAYS_SATISFIED and c not in self_provided
    ]
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
