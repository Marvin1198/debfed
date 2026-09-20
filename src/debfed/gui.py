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


# The activation token the launcher minted for this process. It grants
# focus to exactly one window on Wayland and is then stale, so it is
# consumed by the first dialog and cleared. Reusing it would at best do
# nothing and at worst confuse the compositor about which surface is
# being activated.
def _take_activation_token() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID"):
        os.environ.pop(name, None)
    return env


class _Progress:
    """A pulsing progress dialog fed over stdin.

    Conversion has two slow phases -- resolving every capability against
    dnf, and building the rpm -- and a 166MB package spends about twenty
    seconds in them. Without this the user gets an unexplained pause and
    no way to tell the difference between working and hung.

    Pulsating rather than percentage: neither phase reports meaningful
    progress, and a fake percentage bar that jumps to 90 and waits is
    worse than an honest indeterminate one.
    """

    def __init__(self, title: str, initial: str, env: dict[str, str] | None = None):
        self._proc = subprocess.Popen(
            [_zenity(), "--progress", "--pulsate", "--auto-close", "--no-cancel",
             f"--title={title}", f"--text={initial}", "--width=420"],
            stdin=subprocess.PIPE, text=True,
            env=env if env is not None else None,
        )

    def step(self, message: str) -> None:
        if self._proc.stdin is None or self._proc.poll() is not None:
            return
        try:
            self._proc.stdin.write(f"# {message}\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass

    def close(self) -> None:
        if self._proc.stdin is not None:
            try:
                self._proc.stdin.close()
            except (BrokenPipeError, ValueError):
                pass
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()

    def __enter__(self) -> _Progress:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


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

    # The first dialog gets the activation token, so it is the one that
    # appears in front. That has to be the progress dialog: inspection
    # runs before anything can be shown, and it is slow.
    launch_env = _take_activation_token()

    with tempfile.TemporaryDirectory(prefix="debfed-gui-") as tmpdir:
        tmp = Path(tmpdir)
        progress = _Progress(f"Inspecting {deb.name}",
                             "Reading package…", env=launch_env)
        try:
            progress.step("Resolving dependencies against Fedora…")
            analysis = analyse(deb, tmp)
        except (DebError, UnsafeInput, ValueError) as exc:
            progress.close()
            _error_dialog(f"{deb.name} cannot be converted.\n\n{exc}")
            return 1
        except ResolveError as exc:
            progress.close()
            _error_dialog(f"Could not check dependencies.\n\n{exc}")
            return 2
        finally:
            progress.close()

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

        build_progress = _Progress(f"Converting {analysis.deb.name}",
                                   "Rewriting paths for Fedora…")
        try:
            build_progress.step("Building the rpm…")
            _, _, result = _build(analysis, tmp, quiet=True)
        except (BuildError, BundleError, UnsafeInput) as exc:
            build_progress.close()
            _error_dialog(f"Conversion failed.\n\n{exc}")
            return 1
        finally:
            build_progress.close()

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

    # No progress dialog here: polkit shows its own, and a second window
    # competing with the authentication prompt would be worse than none.
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
