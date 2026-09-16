"""Make the checkout importable without installing it first.

The project uses a src/ layout, so `debfed` is not importable from the
repository root. CI installs with `pip install -e .` and works; someone
who clones the repo and runs pytest directly does not, and a pipx
install does not help either -- pipx copies the package into its own
virtualenv, which the system python running pytest cannot see.

Prepending src/ here means `pytest` works straight from a clean clone,
and also guarantees the tests exercise the working tree rather than
whatever version happens to be installed elsewhere on the system.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"

if SRC.is_dir():
    sys.path.insert(0, str(SRC))
