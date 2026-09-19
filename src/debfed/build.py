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
            conflicts.append(Conflict(path, name))
            break
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

    owners: dict[str, str] = {}
    wanted = set(paths)
    for line in proc.stdout.splitlines():
        path, sep, name = line.partition("\t")
        if sep and path in wanted:
            owners.setdefault(path, name)
    return [Conflict(p, owners[p]) for p in paths if p in owners]


def find_conflicts(reloc: Relocation) -> list[Conflict]:
    """Which payload files are already owned by an installed rpm.

    Read-only. Catches the alien failure mode before rpm does, with a
    better message.
    """
    if not reloc.files:
        return []
    via_bindings = _conflicts_via_bindings(reloc.files)
    if via_bindings is not None:
        return via_bindings
    return _conflicts_via_bulk_query(reloc.files)


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
    return subprocess.run(cmd).returncode


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
