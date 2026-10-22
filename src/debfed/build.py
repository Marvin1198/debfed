"""Building and installing.

Every destructive step is gated. `debfed install` always prints a dry-run
plan and requires either an interactive confirmation or an explicit
--yes. Nothing is ever written outside rpm ownership: there is no code
path here that copies into /usr.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .layout import Relocation
from .spec import RELEASE_MARKER


class BuildError(Exception):
    pass


def _require(binary: str, package: str) -> str:
    found = shutil.which(binary)
    if not found:
        raise BuildError(f"{binary} not found. Install it:  dnf install {package}")
    return found


@dataclass
class Conflict:
    path: str
    owner: str


def _conflicts_via_bindings(paths: list[str]) -> list[Conflict] | None:
    """Query the rpmdb directly. Correct for paths absent from the host."""
    try:
        import rpm  # type: ignore
    except ImportError:
        return None

    conflicts: list[Conflict] = []
    ts = rpm.TransactionSet()
    for path in paths:
        for header in ts.dbMatch("basenames", path):
            name = header[rpm.RPMTAG_NAME]
            if isinstance(name, bytes):
                name = name.decode()
            # Every owner, not just the first: a path shared by the package
            # being upgraded AND another package is still a real conflict.
            conflicts.append(Conflict(path, name))
    return conflicts


def _conflicts_via_bulk_query(paths: list[str]) -> list[Conflict]:
    """Fallback: read every owned path out of the rpmdb once and intersect.

    `rpm -qf` cannot be used here. It stats each argument, so it fails on
    paths that do not yet exist on the host, and it writes those failures
    to stderr -- which means its stdout lines no longer correspond
    one-to-one with its arguments. Pairing them positionally reports the
    wrong owner for the wrong file.
    """
    rpm_bin = shutil.which("rpm")
    if not rpm_bin:
        return []
    # A tab separator: rpm file names may contain spaces, so splitting on
    # one would attribute the wrong owner to the wrong path.
    proc = subprocess.run(
        [rpm_bin, "-qa", "--qf", "[%{FILENAMES}\t%{NAME}\n]"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return []

    owners: dict[str, list[str]] = {}
    wanted = set(paths)
    for line in proc.stdout.splitlines():
        path, sep, name = line.partition("\t")
        if sep and path in wanted and name not in owners.setdefault(path, []):
            owners[path].append(name)
    return [Conflict(p, o) for p in paths for o in owners.get(p, [])]


CONVERTED_MARKER = "debfed-converted"


def installed_conversion(name: str) -> bool:
    """Is `name` installed AND an earlier debfed conversion?

    Every debfed RPM carries `Provides: debfed-converted`. Only those may
    be upgraded in place; a same-named package from Fedora or a third
    party repo is not ours to replace.
    """
    rpm_bin = shutil.which("rpm")
    if not rpm_bin:
        return False
    proc = subprocess.run(
        [rpm_bin, "-q", "--qf", "%{NAME}\n", "--whatprovides", CONVERTED_MARKER],
        capture_output=True, text=True,
    )
    if proc.returncode == 0 and name in {
        line.strip() for line in proc.stdout.splitlines()
    }:
        return True
    # Backup signal: every marked build also has a Release of the form
    # N.debfed.fcXX, which survives even if the Provides is filtered out.
    proc = subprocess.run(
        [rpm_bin, "-q", "--qf", "%{RELEASE}\n", name],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return False
    marker = RELEASE_MARKER + "."
    return any(marker in line.strip() + "."
               for line in proc.stdout.splitlines())


def find_conflicts(reloc: Relocation, upgrading: str | None = None) -> list[Conflict]:
    """Which payload files are already owned by an installed rpm.

    Read-only. Catches the alien failure mode before rpm does, with a
    better message.

    `upgrading` names the package this build replaces. Its files are not
    conflicts: rpm -U swaps them in one transaction. Without this, every
    upgrade of a converted package was refused -- Claude Desktop
    2.9939.4 -> 3.6556.1 reported 1110 "conflicts", all owned by
    claude-desktop itself. The caller passes it only for a debfed
    conversion (see installed_conversion).
    """
    if not reloc.files:
        return []
    found = _conflicts_via_bindings(reloc.files)
    if found is None:
        found = _conflicts_via_bulk_query(reloc.files)
    if upgrading:
        found = [c for c in found if c.owner != upgrading]
    return found


@dataclass
class BuildResult:
    spec_path: Path
    rpm_path: Path
    log: str = ""
    warnings: list[str] = field(default_factory=list)


def build_rpm(
    spec_text: str,
    payload_dir: Path,
    name: str,
    workdir: Path,
    *,
    quiet: bool = True,
) -> BuildResult:  # noqa: ARG001 - `name` kept for call-site clarity
    """Render the spec to disk and run rpmbuild against the staged payload."""
    rpmbuild = _require("rpmbuild", "rpm-build")

    topdir = workdir / "rpmbuild"
    for sub in ("SPECS", "SOURCES", "BUILD", "BUILDROOT", "RPMS", "SRPMS"):
        (topdir / sub).mkdir(parents=True, exist_ok=True)

    # The spec filename must NOT be derived from the package name. A
    # Package: field of "../../../../tmp/x" would otherwise place the
    # spec anywhere on the filesystem -- an arbitrary file write from a
    # crafted .deb. The name is validated upstream too; this is the
    # second line of defence, and the cheap one.
    spec_path = topdir / "SPECS" / "debfed-generated.spec"
    spec_path.write_text(spec_text)

    cmd = [
        rpmbuild,
        "-bb",
        "--define", f"_topdir {topdir}",
        "--define", f"debfed_payload {payload_dir}",
        "--define", "_binary_payload w2.xzdio",
        str(spec_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    log = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise BuildError(
            f"rpmbuild failed (exit {proc.returncode}).\n"
            + "\n".join(log.splitlines()[-25:])
        )

    built = sorted((topdir / "RPMS").rglob("*.rpm"))
    if not built:
        raise BuildError("rpmbuild reported success but produced no rpm")

    warnings = [ln for ln in log.splitlines() if "warning:" in ln.lower()]
    return BuildResult(spec_path=spec_path, rpm_path=built[-1], log=log,
                       warnings=warnings)


# ------------------------------------------------------------------ install


def verify_requires(rpm_path: Path, blocking: list[str]) -> list[str]:
    """Capabilities the built RPM still requires that nothing can satisfy.

    The analysis and the generated package are produced by different
    code, and they have drifted twice: once when the spec did not carry
    the analysis's exclusions, and once when `build` reimplemented the
    pipeline and skipped bundling. Both times debfed reported success
    and produced an RPM dnf refused to install.

    Reading the finished artifact is the only check that cannot drift,
    because it inspects the thing the user actually receives.
    """
    rpm_bin = shutil.which("rpm")
    if not rpm_bin or not blocking:
        return []
    proc = subprocess.run(
        [rpm_bin, "-qp", "--requires", str(rpm_path)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return []
    present = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    return sorted(present & set(blocking))


# What dnf prints when --assumeno ends the preview. In a dry run that is
# the expected outcome, but the wording reads like a failure.
_ASSUMENO_NOISE = ("Operation aborted by the user", "Operation aborted.")


def dnf_install(rpm_path: Path, *, assume_yes: bool, test: bool = False) -> int:
    """Hand the built rpm to dnf so it owns resolution and the transaction."""
    dnf = _require("dnf", "dnf")
    cmd = [dnf, "install", str(rpm_path)]
    if test:
        cmd.append("--assumeno")
    elif assume_yes:
        cmd.append("-y")
    if os.geteuid() != 0:
        cmd = [_require("sudo", "sudo"), *cmd]
    if not test:
        return subprocess.run(cmd).returncode
    # sudo prompts on the terminal, not stdout, so capturing is safe.
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout.splitlines():
        if line.strip().startswith(_ASSUMENO_NOISE):
            continue
        print(line)
    return proc.returncode


def repo_same_name(name: str) -> list[str]:
    """Builds of `name` in the enabled repositories, as name-evr strings.

    A converted package that shares its name with a Fedora package will be
    replaced by Fedora's build on the next upgrade, because the .debfed
    release marker sorts lower. The user should know that before
    installing, and usually wants Fedora's build instead.
    """
    dnf = shutil.which("dnf5") or shutil.which("dnf")
    if not dnf:
        return []
    proc = subprocess.run(
        [dnf, "repoquery", "--quiet", "--available",
         "--qf", "%{name}-%{evr} (%{repo_id})\n", name],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return []
    return sorted({ln.strip() for ln in proc.stdout.splitlines() if ln.strip()})


def dnf_remove(name: str, *, assume_yes: bool) -> int:
    dnf = _require("dnf", "dnf")
    cmd = [dnf, "remove", name]
    if assume_yes:
        cmd.append("-y")
    if os.geteuid() != 0:
        cmd = [_require("sudo", "sudo"), *cmd]
    return subprocess.run(cmd).returncode


def rpm_query_installed(name: str) -> str | None:
    rpm = shutil.which("rpm")
    if not rpm:
        return None
    proc = subprocess.run(
        [rpm, "-q", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}", name],
        capture_output=True, text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else None
