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


class Suite:
    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.results: list[tuple[str, bool, str]] = []

    def run_debfed(self, *args: str) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, "-m", "debfed", *args],
            capture_output=True, text=True, timeout=300,
        )
        return proc.returncode, (proc.stdout + proc.stderr)

    def check(self, name: str, deb: Path, markers: list[Path]) -> None:
        """Build the hostile package; assert no marker was created."""
        for marker in markers:
            if marker.exists():
                marker.unlink()
        out_dir = self.workdir / "out"
        _, output = self.run_debfed(
            "build", "--offline", "-o", str(out_dir), str(deb)
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


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="debfed-attacks-") as tmp:
        tmp = Path(tmp)
        marker_dir = tmp / "markers"
        marker_dir.mkdir()
        outside = tmp / "outside"
        outside.mkdir()

        suite = Suite(tmp)
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
    sys.exit(main())
