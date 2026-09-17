"""Locating and invoking the debfed CLI from a test harness.

This exists because the same bug has now appeared twice. A harness that
runs `python3 -m debfed` works under `pip install -e .` and fails under
pipx, which copies the package into a private virtualenv the system
python cannot see. When the invocation fails, every package looks like it
was refused -- a plausible-looking result from a harness that never ran
anything.

Both the exploit suite and the corpus harness resolve the CLI through
here, so the fix cannot apply to one and not the other.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"


class CliUnavailable(Exception):
    """debfed could not be invoked; any results would be meaningless."""


def resolve_invocation(verbose: bool = True) -> list[str]:
    """Return a command prefix that actually runs debfed, or raise.

    Tried in order: an installed module, the console script, then the
    working tree. Each candidate must answer --version before it is
    accepted -- "the command exists" is not the same as "the command
    works".
    """
    candidates = [
        [sys.executable, "-m", "debfed"],   # pip install -e . / pip install
        ["debfed"],                          # console script (pipx)
    ]
    for inv in candidates:
        try:
            proc = subprocess.run([*inv, "--version"], capture_output=True,
                                  text=True, timeout=60)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0 and "debfed" in proc.stdout:
            if verbose:
                print(f"  using: {' '.join(inv)}  ({proc.stdout.strip()})")
            return inv

    # Last resort: the working tree, so a clean clone can be tested
    # without installing anything.
    if SRC.is_dir():
        inv = [sys.executable, "-m", "debfed"]
        env = {**os.environ, "PYTHONPATH": str(SRC)}
        try:
            proc = subprocess.run([*inv, "--version"], capture_output=True,
                                  text=True, timeout=60, env=env)
            if proc.returncode == 0 and "debfed" in proc.stdout:
                os.environ["PYTHONPATH"] = str(SRC)
                if verbose:
                    print(f"  using: working tree at {SRC}  "
                          f"({proc.stdout.strip()})")
                return inv
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass

    raise CliUnavailable(
        "debfed is not runnable. Tried:\n"
        f"  {sys.executable} -m debfed\n"
        "  debfed\n"
        f"  {sys.executable} -m debfed with PYTHONPATH={SRC}\n\n"
        "Install it first:  pipx install --system-site-packages .\n"
        "Refusing to continue: a harness that cannot run debfed reports\n"
        "every package as refused, which looks like a result and is not."
    )


# debfed exit codes: 0 built, 1 verdict about the package, 2 could not
# decide. Only 0 and 1 mean debfed reached a conclusion.
VERDICT_CODES = (0, 1)

DID_NOT_RUN = (
    "No module named",
    "command not found",
    "ModuleNotFoundError",
    "ImportError",
    "Traceback (most recent call last)",
    "not found. Install it",
)


def ran_successfully(returncode: int, output: str) -> bool:
    """False when debfed failed to execute rather than reaching a verdict."""
    if returncode not in VERDICT_CODES:
        return False
    return not any(sig in output for sig in DID_NOT_RUN)
