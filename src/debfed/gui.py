"""Graphical install flow, for double-clicking a package in a file manager.

The shape matters more than the widgets:

    convert as the calling user   (no privileges needed at all)
        -> show what will happen  (unprivileged dialog)
            -> one polkit prompt  (the only escalation)

Converting a .deb needs no root: reading the archive, resolving
dependencies, generating the spec and building the RPM all happen in a
temporary directory owned by the user. Only handing the finished package
to dnf requires privilege, so that is the only step that escalates, and
it escalates through the system's own authentication dialog.

debfed never sees a password. pkexec reports authorised or not, and
nothing more. An application that collects the password itself is
indistinguishable from a phishing dialog, whatever it says in the title
bar.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HELPER = "/usr/bin/debfed-install"
PKEXEC = "/usr/bin/pkexec"


class GuiUnavailable(Exception):
    """No usable dialog programme; the caller should fall back to a terminal."""


def _zenity() -> str:
    path = shutil.which("zenity")
    if path is None:
        raise GuiUnavailable(
            "zenity is not installed, so the graphical flow cannot run.\n"
            "Install it:  dnf install zenity\n"
            "Or convert from a terminal:  debfed install <package.deb>"
        )
    return path


def _notify(summary: str, body: str = "", urgency: str = "normal") -> None:
    notify = shutil.which("notify-send")
    if notify:
        subprocess.run([notify, "-u", urgency, "-a", "debfed", summary, body],
                       capture_output=True)


def _error_dialog(message: str) -> None:
    try:
        zenity = _zenity()
    except GuiUnavailable:
        print(message, file=sys.stderr)
        return
    subprocess.run([zenity, "--error", "--title=debfed",
                    "--width=560", f"--text={message}"], capture_output=True)


def _confirm(title: str, body: str, ok_label: str) -> bool:
    """Show the full report and ask once. False means the user declined."""
    zenity = _zenity()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(body)
        report = handle.name
    try:
        proc = subprocess.run(
            [zenity, "--text-info", f"--title={title}", f"--filename={report}",
             "--width=760", "--height=560",
             f"--ok-label={ok_label}", "--cancel-label=Cancel"],
        )
        return proc.returncode == 0
    finally:
        os.unlink(report)


def _strip_colour(text: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def install(deb: Path, *, verbose: bool = False) -> int:
    """Convert, show the outcome, then escalate once to install."""
    from .build import BuildError
    from .bundle import BundleError
    from .cli import _build, analyse, print_inspect
    from .deb import DebError
    from .depsolve import ResolveError
    from .refuse import Verdict
    from .sanitize import UnsafeInput

    try:
        _zenity()
    except GuiUnavailable as exc:
        print(exc, file=sys.stderr)
        return 2

    if not deb.is_file():
        _error_dialog(f"No such file:\n{deb}")
        return 2

    _notify("Inspecting package", deb.name)

    with tempfile.TemporaryDirectory(prefix="debfed-gui-") as tmpdir:
        tmp = Path(tmpdir)
        try:
            analysis = analyse(deb, tmp)
        except (DebError, UnsafeInput, ValueError) as exc:
            _error_dialog(f"{deb.name} cannot be converted.\n\n{exc}")
            return 1
        except ResolveError as exc:
            _error_dialog(f"Could not check dependencies.\n\n{exc}")
            return 2

        # Capture the same report the terminal would print.
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            print_inspect(analysis, verbose=verbose)
        report = _strip_colour(buffer.getvalue())

        if analysis.assessment.verdict is Verdict.REFUSE:
            _error_dialog(
                f"{analysis.deb.name} cannot be installed on this system.\n\n"
                f"{analysis.assessment.reason}"
            )
            return 1

        if not _confirm(f"Install {analysis.deb.name}?", report, "Convert"):
            return 1

        _notify("Converting", f"{analysis.deb.name} {analysis.deb.version}")
        try:
            _, _, result = _build(analysis, tmp, quiet=True)
        except (BuildError, BundleError, UnsafeInput) as exc:
            _error_dialog(f"Conversion failed.\n\n{exc}")
            return 1

        # The RPM lives in a temporary directory that disappears with this
        # block, so hand the helper a copy that outlives it.
        staged = Path(tempfile.gettempdir()) / result.rpm_path.name
        shutil.copy2(result.rpm_path, staged)

    try:
        return _escalate_and_install(staged, analysis.deb.name)
    finally:
        staged.unlink(missing_ok=True)


def _escalate_and_install(rpm: Path, name: str) -> int:
    """The only privileged step. pkexec shows the system's own dialog."""
    if not Path(PKEXEC).exists():
        _error_dialog("pkexec is not available, so the package cannot be "
                      "installed graphically.\n\n"
                      f"Install it from a terminal:\n  sudo dnf install {rpm}")
        return 2
    if not Path(HELPER).exists():
        _error_dialog(
            "The debfed install helper is missing.\n\n"
            "The graphical flow needs debfed installed as an RPM; a pipx or "
            "pip installation does not provide the helper or its polkit "
            "action."
        )
        return 2

    proc = subprocess.run([PKEXEC, HELPER, str(rpm)],
                          capture_output=True, text=True)

    if proc.returncode == 0:
        _notify("Installed", name)
        return 0

    # pkexec exits 126 when the user dismisses the dialog or authorisation
    # is refused, and 127 when the helper could not be run at all.
    if proc.returncode == 126:
        _notify("Installation cancelled", name, urgency="low")
        return 1
    if proc.returncode == 127:
        _error_dialog("The install helper could not be started.")
        return 2

    tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-12:])
    _error_dialog(f"Installing {name} failed.\n\n{tail}")
    return proc.returncode
