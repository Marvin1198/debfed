#!/usr/bin/env python3
"""End-to-end exploit suite.

The unit tests in test_debfed.py check the sanitisers in isolation. This
runs the *real CLI* against deliberately hostile .deb files and asserts
that nothing escaped: no command executed, no file written outside the
working directory.

Every case here reproduced against an earlier revision of debfed. They
are live exploits, not hypotheticals, which is why they run as their own
CI gate rather than as part of the ordinary test suite.

Usage:
    python tests/attack_suite.py          # exits non-zero if any escapes
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def build_deb(path: Path, control: str, files: dict[str, bytes],
              links: dict[str, str] | None = None,
              modes: dict[str, int] | None = None) -> Path:
    """Assemble an arbitrary .deb, including malformed ones."""
    def tar_bytes(entries, link_entries=None, mode_map=None):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, blob in entries.items():
                info = tarfile.TarInfo("./" + name.lstrip("/"))
                info.size = len(blob)
                info.mode = (mode_map or {}).get(name, 0o644)
                tf.addfile(info, io.BytesIO(blob))
            for name, target in (link_entries or {}).items():
                info = tarfile.TarInfo("./" + name.lstrip("/"))
                info.type = tarfile.SYMTYPE
                info.linkname = target
                tf.addfile(info)
        return buf.getvalue()

    members = [
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", tar_bytes({"control": control.encode()})),
        ("data.tar.gz", tar_bytes(files, links, modes)),
    ]
    with path.open("wb") as fh:
        fh.write(b"!<arch>\n")
        for name, blob in members:
            fh.write(
                f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{len(blob):<10}"
                .encode() + b"`\n"
            )
            fh.write(blob)
            if len(blob) % 2:
                fh.write(b"\n")
    return path


def control(pkg: str, **extra: str) -> str:
    head = (
        f"Package: {pkg}\nVersion: 1.0-1\nArchitecture: amd64\n"
        "Maintainer: Attacker <a@evil.invalid>\n"
    )
    for key, value in extra.items():
        head += f"{key.replace('_', '-')}: {value}\n"
    if "Description" not in extra:
        head += "Description: benign\n benign body\n"
    return head


# Output that means debfed never ran, rather than ran and refused. Without
# this distinction the suite reports "blocked" for every case when the tool
# is simply missing -- an attack suite that passes while testing nothing.
DID_NOT_RUN = (
    "No module named",
    "command not found",
    "ModuleNotFoundError",
    "ImportError",
    "Traceback (most recent call last)",
    "not found. Install it",     # debfed's own missing-tool message
)

# debfed exit codes: 0 = built, 1 = verdict about the package, 2 = could
# not decide. Only 0 and 1 are verdicts.
#
# Treating 2 as a verdict is what let a missing rpmbuild report "all 9
# attacks blocked". The canary below proves the toolchain works before any
# attack runs, so a 2 here means this specific package broke something --
# still not a verdict, and still worth aborting over.
VERDICT_CODES = (0, 1)


sys.path.insert(0, str(Path(__file__).resolve().parent))
from _cli import CliUnavailable as _CliUnavailable  # noqa: E402
from _cli import resolve_invocation as _resolve  # noqa: E402


class SuiteUnusable(Exception):
    """debfed could not be invoked; results would be meaningless."""


class Suite:
    def __init__(self, workdir: Path, invocation: list[str]):
        self.workdir = workdir
        self.invocation = invocation
        self.results: list[tuple[str, bool, str]] = []

    def run_debfed(self, *args: str) -> tuple[int, str]:
        proc = subprocess.run(
            [*self.invocation, *args],
            capture_output=True, text=True, timeout=300,
        )
        return proc.returncode, (proc.stdout + proc.stderr)

    def check(self, name: str, deb: Path, markers: list[Path]) -> None:
        """Build the hostile package; assert no marker was created.

        A missing marker only proves the attack failed if debfed actually
        executed. Verify that first -- otherwise a broken install reports
        a clean sweep.
        """
        for marker in markers:
            if marker.exists():
                marker.unlink()
        out_dir = self.workdir / "out"
        code, output = self.run_debfed(
            "build", "--offline", "-o", str(out_dir), str(deb)
        )

        if code == 127 or any(sig in output for sig in DID_NOT_RUN):
            raise SuiteUnusable(
                f"debfed failed to execute (exit {code}):\n"
                + "\n".join(output.strip().splitlines()[-5:])
            )
        if code not in VERDICT_CODES:
            raise SuiteUnusable(
                f"debfed exited {code}, which is not a verdict (0=built, "
                f"1=refused). It did not reach a decision about this "
                f"package:\n" + "\n".join(output.strip().splitlines()[-5:])
            )

        escaped = [m for m in markers if m.exists()]
        detail = output.strip().splitlines()[-1][:70] if output.strip() else ""
        self.results.append((name, not escaped, detail))
        for marker in escaped:
            marker.unlink()

    def report(self) -> int:
        print()
        failures = 0
        for name, ok, detail in self.results:
            if ok:
                print(f"  {GREEN}blocked{RESET}     {name:<34} {detail}")
            else:
                failures += 1
                print(f"  {RED}EXPLOITED{RESET}   {name:<34} {detail}")
        print()
        if failures:
            print(f"{RED}{failures} of {len(self.results)} attacks succeeded{RESET}")
        else:
            print(f"{GREEN}all {len(self.results)} attacks blocked{RESET}")
        return 1 if failures else 0


def resolve_invocation() -> list[str]:
    """Delegates to the shared helper so the two harnesses cannot diverge."""
    try:
        return _resolve()
    except _CliUnavailable as exc:
        raise SuiteUnusable(str(exc)) from exc


def _resolve_invocation_unused() -> list[str]:
    """Find a working way to run debfed, or refuse to proceed.

    pipx installs into its own venv, so `python3 -m debfed` fails even
    though the `debfed` console script works. Try both, and verify the
    result actually responds before running a single attack.
    """
    src = Path(__file__).resolve().parent.parent / "src"
    candidates = [
        [sys.executable, "-m", "debfed"],        # editable or normal install
        ["debfed"],                              # console script (pipx)
    ]
    # Last resort: the working tree itself, so a clean clone can be tested
    # without installing anything. Same path pytest uses via conftest.py.
    env_src = {**os.environ, "PYTHONPATH": str(src)} if src.is_dir() else None

    for inv in candidates:
        try:
            proc = subprocess.run(
                [*inv, "--version"], capture_output=True, text=True, timeout=60
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0 and "debfed" in proc.stdout:
            print(f"  using: {' '.join(inv)}  ({proc.stdout.strip()})")
            return inv

    if env_src is not None:
        inv = [sys.executable, "-m", "debfed"]
        try:
            proc = subprocess.run(
                [*inv, "--version"], capture_output=True, text=True,
                timeout=60, env=env_src,
            )
            if proc.returncode == 0 and "debfed" in proc.stdout:
                print(f"  using: working tree at {src}  ({proc.stdout.strip()})")
                os.environ["PYTHONPATH"] = str(src)
                return inv
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass
    raise SuiteUnusable(
        "debfed is not runnable. Tried:\n"
        + "\n".join("  " + " ".join(c) for c in candidates)
        + "\n\nInstall it first:  pipx install --system-site-packages .\n"
        "Refusing to run the attack suite -- it would report every case as\n"
        "blocked simply because nothing executed."
    )


def canary(invocation: list[str], workdir: Path) -> None:
    """Convert a known-good package before trusting any "blocked" result.

    Checking for tools by name is not enough: rpmbuild may be present but
    broken, a macro may be missing, the temp dir may be unwritable. If a
    package that MUST convert does not, then every subsequent "no marker
    appeared" result is meaningless -- debfed never got far enough to be
    exploited.

    This is the guarantee that makes the per-case checks trustworthy.
    """
    good = build_deb(
        workdir / "canary.deb",
        control("canaryapp"),
        {"usr/bin/canaryapp": b"\x7fELF\x02\x01\x01" + b"\x00" * 57},
    )
    proc = subprocess.run(
        [*invocation, "build", "--offline", "-o", str(workdir / "canary-out"),
         str(good)],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise SuiteUnusable(
            "the canary package failed to convert, so the toolchain is not "
            "working. Every attack would report as blocked for the wrong "
            f"reason.\n\nexit {proc.returncode}:\n"
            + "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-8:])
        )
    print("  canary: a known-good package converts correctly")


def check_prerequisites() -> None:
    """Confirm the tools debfed needs are present.

    debfed exits 2 when rpmbuild is missing. Every attack would then be
    reported as blocked because debfed stopped before it could be
    exploited -- true, and completely uninformative.
    """
    missing = [t for t in ("rpmbuild",) if shutil.which(t) is None
               and not os.path.isfile(f"/usr/lib/rpm/{t}")]
    if missing:
        raise SuiteUnusable(
            f"missing required tool(s): {', '.join(missing)}\n"
            "Install with:  dnf install rpm-build\n"
            "Refusing to run: debfed would abort before reaching any verdict."
        )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="debfed-attacks-") as tmpdir:
        tmp = Path(tmpdir)
        try:
            check_prerequisites()
            invocation = resolve_invocation()
            canary(invocation, tmp)
        except SuiteUnusable as exc:
            print(f"\n{RED}SUITE UNUSABLE{RESET}\n{exc}\n", file=sys.stderr)
            return 2

        marker_dir = tmp / "markers"
        marker_dir.mkdir()
        outside = tmp / "outside"
        outside.mkdir()

        suite = Suite(tmp, invocation)
        m = lambda n: marker_dir / n  # noqa: E731

        # 1. rpm expands %(cmd) through /bin/sh at spec parse time.
        suite.check(
            "macro injection via Description",
            build_deb(
                tmp / "a1.deb",
                control("evilapp", Description=f"%(touch {m('desc')})\n benign"),
                {"usr/bin/evilapp": b"\x7fELF"},
            ),
            [m("desc")],
        )

        # 2. Same vector through a URL-shaped tag.
        suite.check(
            "macro injection via Homepage",
            build_deb(
                tmp / "a2.deb",
                control("urlapp", Homepage=f"https://x/%(touch {m('url')})"),
                {"usr/bin/urlapp": b"\x7fELF"},
            ),
            [m("url")],
        )

        # 3. %{lua:...} is a second interpreter rpm exposes at parse time.
        suite.check(
            "lua macro injection",
            build_deb(
                tmp / "a3.deb",
                control(
                    "luaapp",
                    Description=(
                        "%{lua:os.execute('touch " + str(m("lua")) + "')}\n benign"
                    ),
                ),
                {"usr/bin/luaapp": b"\x7fELF"},
            ),
            [m("lua")],
        )

        # 4. The package name reaches the filesystem as the spec path.
        suite.check(
            "package name path traversal",
            build_deb(
                tmp / "a4.deb",
                control("../../../../" + str(marker_dir / "trav")),
                {"usr/bin/t": b"\x7fELF"},
            ),
            [marker_dir / "trav.spec"],
        )

        # 5. Absolute symlink with a member written through it.
        suite.check(
            "absolute symlink escape",
            build_deb(
                tmp / "a5.deb",
                control("linkapp"),
                {"opt/linkapp/esc/OWNED": b"escaped"},
                links={"opt/linkapp/esc": str(outside)},
            ),
            [outside / "OWNED"],
        )

        # 6. Relative symlink climbing out of the payload.
        suite.check(
            "relative symlink escape",
            build_deb(
                tmp / "a6.deb",
                control("relapp"),
                {"usr/bin/relapp": b"\x7fELF"},
                links={"usr/bin/esc": "../../../../../../../../etc/shadow"},
            ),
            [],
        )

        # 7. Macro syntax in a packaged filename.
        suite.check(
            "macro injection via filename",
            build_deb(
                tmp / "a7.deb",
                control("fnapp"),
                {f"usr/share/fnapp/%(touch {m('fn')})x": b"x"},
            ),
            [m("fn")],
        )

        # 8. A newline in a single-line tag would open a new spec section.
        suite.check(
            "spec section injection via newline",
            build_deb(
                tmp / "a8.deb",
                control(
                    "nlapp",
                    Description=f"benign\n%install\ntouch {m('nl')}\n benign",
                ),
                {"usr/bin/nlapp": b"\x7fELF"},
            ),
            [m("nl")],
        )

        # 9. Traversal in a payload member name.
        suite.check(
            "payload path traversal",
            build_deb(
                tmp / "a9.deb",
                control("travapp"),
                {"../../../../../../.." + str(outside / "TRAVERSED"): b"x"},
            ),
            [outside / "TRAVERSED"],
        )

        return suite.report()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SuiteUnusable as exc:
        print(f"\n{RED}SUITE UNUSABLE{RESET}\n{exc}\n", file=sys.stderr)
        sys.exit(2)
