#!/usr/bin/env python3
"""Corpus harness: measure debfed against many real packages at once.

Testing one application at a time produces anecdotes. Every serious bug
in this project was found by running a diverse sample and looking at the
distribution of outcomes -- foreign-architecture binaries, the inverted
glibc check, directory ownership, Pre-Depends, triggers. None of them
were visible from a single package.

Two modes:

    --fetch     download a diverse sample from the Ubuntu archive
    --measure   inspect every package and report verdicts by frequency
    --run       install each converted RPM and execute what it ships

`--run` is the one that matters: building an RPM proves nothing about
whether the application starts.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = "http://archive.ubuntu.com/ubuntu/pool"
HERE = pathlib.Path(__file__).resolve().parent
DEBS = HERE / "debs"
RPMS = HERE / "rpms"

# Deliberately diverse: GUI apps, CLI tools, daemons, fonts, games,
# browsers, libraries, and a few packages that MUST be refused.
SAMPLE = """tree sl hello jq htop ncdu neofetch galculator mousepad xterm
rxvt-unicode feh scrot gpick nano zsh fish tmux mc fonts-inconsolata
hicolor-icon-theme adwaita-icon-theme sqlite3 rsync curl wget cmatrix
cowsay figlet lolcat dosbox xarchiver gnome-mines memcached
ca-certificates desktop-file-utils shared-mime-info gedit gnome-calculator
vlc audacity inkscape geany meld filezilla keepassxc thunderbird
openssh-server cups network-manager bluez dbus sudo bash coreutils
systemd""".split()


def fetch_one(pkg: str) -> str:
    first = pkg[:4] if pkg.startswith("lib") else pkg[0]
    for section in ("main", "universe"):
        url = f"{BASE}/{section}/{first}/{pkg}/"
        try:
            html = urllib.request.urlopen(url, timeout=30).read().decode("latin1")
        except Exception:
            continue
        names = sorted(set(re.findall(
            rf'({re.escape(pkg)}_[^"\']*?_(?:amd64|all)\.deb)', html)))
        if not names:
            continue
        dest = DEBS / names[-1]
        if dest.exists():
            return f"have {names[-1]}"
        try:
            urllib.request.urlretrieve(url + names[-1], dest)
            return f"ok   {names[-1]}"
        except Exception as exc:
            return f"FAIL {pkg}: {exc}"
    return f"MISS {pkg}"


def cmd_fetch(_args) -> int:
    DEBS.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=8) as pool:
        for line in pool.map(fetch_one, SAMPLE):
            print(" ", line)
    print(f"\ncorpus: {len(list(DEBS.glob('*.deb')))} packages")
    return 0


def _debfed(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "debfed", *args],
                          capture_output=True, text=True, timeout=timeout)


def cmd_measure(args) -> int:
    rows = []
    for deb in sorted(DEBS.glob("*.deb")):
        flags = ["inspect", "--json"]
        if args.offline:
            flags.append("--offline")
        p = _debfed(*flags, str(deb))
        if "Traceback (most recent call last)" in p.stdout + p.stderr:
            rows.append({"package": deb.name, "verdict": "CRASH", "findings": []})
            continue
        try:
            rows.append(json.loads(p.stdout)[0])
        except Exception:
            rows.append({"package": deb.name, "verdict": "ERROR", "findings": []})

    (HERE / "results.json").write_text(json.dumps(rows, indent=1))
    verdicts = collections.Counter(r["verdict"] for r in rows)
    print(f"corpus: {len(rows)} packages\n\nVERDICTS")
    for v, n in verdicts.most_common():
        print(f"  {v:<16} {n:>3}  {100 * n / len(rows):.0f}%")

    fatal = collections.Counter()
    warn = collections.Counter()
    for r in rows:
        for f in r.get("findings", []):
            (fatal if f["severity"] == "fatal" else warn)[f["code"]] += 1
    for title, counter in (("FATAL", fatal), ("WARN", warn)):
        print(f"\n{title}")
        for code, n in counter.most_common(12):
            print(f"  {code:<20} {n:>3}")

    crashes = verdicts["CRASH"] + verdicts["ERROR"]
    if crashes:
        print(f"\n{crashes} package(s) crashed debfed -- always a bug")
        return 1
    return 0


def cmd_run(_args) -> int:
    """Install every converted package and execute what it ships."""
    if shutil.which("rpm") is None:
        print("rpm not found", file=sys.stderr)
        return 2
    RPMS.mkdir(parents=True, exist_ok=True)
    results = collections.Counter()
    detail = collections.defaultdict(list)

    for deb in sorted(DEBS.glob("*.deb")):
        build = _debfed("build", "-o", str(RPMS), str(deb))
        if build.returncode == 1:
            results["refused"] += 1
            continue
        if build.returncode != 0:
            results["build failed"] += 1
            detail["build failed"].append(deb.name)
            continue

        name = deb.name.split("_")[0]
        rpms = sorted(RPMS.glob(f"{name}-*.rpm"))
        if not rpms:
            results["no rpm produced"] += 1
            continue

        root = HERE / "root"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        subprocess.run(["rpm", "-i", "--root", str(root), "--nodeps",
                        "--noscripts", str(rpms[-1])],
                       capture_output=True, text=True)

        bins = [b for d in ("usr/bin", "usr/sbin", "usr/games")
                for b in (root / d).glob("*")
                if b.is_file() and os.access(b, os.X_OK)]
        if not bins:
            results["no executable shipped"] += 1
            continue

        proc = subprocess.run([str(bins[0]), "--version"], capture_output=True,
                              text=True, timeout=30)
        out = proc.stdout + proc.stderr
        if "symbol lookup error" in out or "undefined symbol" in out:
            results["symbol mismatch"] += 1
            m = re.search(r"undefined symbol: (\S+)", out)
            detail["symbol mismatch"].append(
                f"{name}: {m.group(1) if m else '?'}")
        elif "cannot open shared object" in out:
            results["missing library"] += 1
            detail["missing library"].append(name)
        elif "Can't locate" in out or "ModuleNotFoundError" in out:
            results["interpreter module missing"] += 1
            detail["interpreter module missing"].append(name)
        else:
            results["RUNS"] += 1

    total = sum(results.values()) or 1
    print(f"executed {total} packages\n")
    for k, n in results.most_common():
        print(f"  {k:<28} {n:>3}  {100 * n / total:.0f}%")
    for k, items in detail.items():
        if items:
            print(f"\n{k}:")
            for d in items[:10]:
                print(f"   {d}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch").set_defaults(func=cmd_fetch)
    m = sub.add_parser("measure")
    m.add_argument("--offline", action="store_true",
                   help="skip dnf resolution (structure only)")
    m.set_defaults(func=cmd_measure)
    sub.add_parser("run").set_defaults(func=cmd_run)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
