"""debfed command line interface.

Exit codes are a contract, not an afterthought -- callers (and debfed's
own exploit suite) must be able to tell a verdict about the package from
a failure to reach one:

    0   success: inspected, built or installed
    1   verdict: the package was refused, or the user aborted
    2   could not decide: a required tool is missing, or the file is
        unreadable

Conflating 1 and 2 means a missing rpmbuild looks like a clean refusal,
which is how an earlier revision of the attack suite reported nine
blocked exploits while testing nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from . import mapping as mapdb
from .build import (
    BuildError,
    build_rpm,
    dnf_install,
    dnf_remove,
    find_conflicts,
    rpm_query_installed,
    verify_requires,
)
from .bundle import BundleError, apply_bundle, plan_bundle, verify_bundle
from .deb import Deb, DebError, unpack
from .depsolve import Resolution, ResolveError, resolve
from .layout import Relocation, relocate
from .refuse import SAFE_TRIGGERS, Assessment, Severity, Verdict, assess
from .runtime import probe as probe_host
from .sanitize import UnsafeInput
from .scripts import ScriptPlan, analyse_scripts, extract_symlinks
from .spec import plan_spec, render

BOLD, DIM, RED, YELLOW, GREEN, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[32m", "\033[0m"
)


def _c(text: str, colour: str) -> str:
    return text if not sys.stdout.isatty() else f"{colour}{text}{RESET}"


class Analysis:
    def __init__(self, deb: Deb, reloc: Relocation, res: Resolution,
                 assessment: Assessment, scripts: ScriptPlan,
                 extra_requires: list[str], unmapped: list[str],
                 offline: bool = False):
        self.deb = deb
        self.reloc = reloc
        self.res = res
        self.assessment = assessment
        self.scripts = scripts
        self.extra_requires = extra_requires
        self.unmapped = unmapped
        self.offline = offline
        # Sonames copied into the private prefix, so the spec can declare
        # each one as Fedora's bundled software policy requires.
        self.bundled_sonames: list[str] = []


def _materialise_launchers(deb: Deb, reloc: Relocation) -> list[str]:
    """Create, inside the buildroot, the launcher symlinks a maintainer
    script would have made, so rpm owns and removes them."""
    created: list[str] = []
    for link, target in extract_symlinks(deb.maintainer_scripts, deb.name):
        if link in reloc.symlinks or link in reloc.files:
            continue
        # The target must be something this package actually ships.
        if target not in reloc.files and target not in reloc.symlinks:
            continue
        path = reloc.buildroot / link.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or path.exists():
            continue
        os.symlink(target, path)
        reloc.symlinks[link] = target
        created.append(link)
    if created:
        reloc.dirs.extend(
            d for d in {c.rsplit("/", 1)[0] for c in created}
            if d not in reloc.dirs
        )
        reloc.dirs.sort()
    return created


def analyse(deb_path: Path, workdir: Path, *, offline: bool = False,
            map_file: Path | None = None,
            strict_scripts: bool = False) -> Analysis:
    deb = unpack(deb_path, workdir)
    reloc = relocate(deb.payload_dir, workdir / "buildroot")
    res = resolve(reloc.buildroot, offline=offline)
    assessment = assess(deb, reloc, res, strict_scripts=strict_scripts)
    scripts = analyse_scripts(deb.maintainer_scripts, deb.triggers, SAFE_TRIGGERS)

    # Restore launchers the maintainer script would have created. Many
    # vendor packages ship the application under /usr/share or /opt and
    # create the /usr/bin entry in postinst, so without this the package
    # installs correctly and is then not on PATH.
    _materialise_launchers(deb, reloc)

    db = mapdb.load(map_file)
    extra_requires, unmapped = db.resolve_all([d.name for d in deb.depends])

    return Analysis(deb, reloc, res, assessment, scripts, extra_requires,
                    unmapped, offline=offline)


# --------------------------------------------------------------- reporting


def print_inspect(an: Analysis, verbose: bool = False) -> None:
    deb, reloc, res, a = an.deb, an.reloc, an.res, an.assessment
    w = sys.stdout.write

    w(f"\n{_c(deb.name, BOLD)} {deb.version}  ({deb.architecture})\n")
    if deb.summary:
        w(f"  {deb.summary}\n")
    w("\n")

    w(f"  {_c('payload', DIM)}      {len(reloc.files)} files, "
      f"{len(reloc.symlinks)} symlinks, {len(reloc.dirs)} dirs\n")
    w(f"  {_c('rewrites', DIM)}     {len(reloc.rewrites)} paths translated\n")
    if reloc.private_prefixes:
        w(f"  {_c('prefixes', DIM)}     {', '.join(reloc.private_prefixes)}\n")
    scripts = list(deb.maintainer_scripts)
    w(f"  {_c('scripts', DIM)}      {', '.join(scripts) if scripts else 'none'}\n")

    w(f"\n  {_c('Debian Depends', DIM)} ({len(deb.depends)}) "
      f"{_c('- sonames are authoritative; these inform extras only', DIM)}\n")
    if deb.depends:
        w(f"    {', '.join(d.name for d in deb.depends)}\n")

    w(f"\n  {_c('rpm requires', BOLD)}  {len(res.requires)} capabilities   ")
    if an.offline:
        w(_c("(dnf resolution skipped: --offline)", DIM))
    else:
        w(_c(f"{len(res.satisfied)} satisfied", GREEN))
        if res.unsatisfied:
            w(f"   {_c(f'{len(res.unsatisfied)} UNSATISFIED', RED)}")
    w("\n")

    for cap in res.unsatisfied:
        w(f"    {_c('MISSING', RED)}  {cap}\n")

    if res.symbol_version_only:
        w(f"  {_c('symbol-version', DIM)} {len(res.symbol_version_only)} "
          f"{_c('differ only by a distribution symbol label', DIM)}\n")

    if res.self_satisfied:
        w(f"  {_c('self-provided', DIM)} {len(res.self_satisfied)} capabilities "
          f"{_c('come from the payload itself', DIM)}\n")
        if verbose:
            for cap in res.self_satisfied:
                w(f"    {cap}\n")

    if res.foreign:
        total = sum(len(v) for v in res.foreign.values())
        kinds = ", ".join(f"{k} x{len(v)}" for k, v in sorted(res.foreign.items()))
        w(f"  {_c('other arches', DIM)}  {total} binaries skipped ({kinds})\n")
        if verbose:
            for kind, paths in sorted(res.foreign.items()):
                for path in paths[:5]:
                    w(f"    {kind}: {path}\n")

    if res.fedora_packages:
        w(f"\n  {_c('resolves to', DIM)}   {', '.join(res.fedora_packages)}\n")

    if an.extra_requires:
        w(f"  {_c('mapped extras', DIM)} {', '.join(an.extra_requires)}\n")
    if an.unmapped and verbose:
        w(f"  {_c('unmapped', DIM)}      {', '.join(an.unmapped)} "
          f"{_c('(no soname, no mapping - likely harmless)', DIM)}\n")

    if res.provides:
        w(f"\n  {_c('would provide', DIM)} {len(res.provides)} capabilities "
          f"{_c('- filtered out of the spec', DIM)}\n")
        if verbose:
            for p in res.provides:
                w(f"    {p}\n")

    if an.scripts.translated or an.scripts.stripped:
        w(f"\n  {_c('maintainer scripts', BOLD)}\n")
        for item in an.scripts.translated:
            w(f"    {_c('keep ', GREEN)} {item}\n")
        for item in an.scripts.stripped:
            w(f"    {_c('strip', YELLOW)} {item}\n")
        if verbose:
            for item in an.scripts.unrecognised[:15]:
                w(f"    {_c('skip ', DIM)} {item}\n")

    if verbose and reloc.rewrites:
        w(f"\n  {_c('path rewrites', DIM)}\n")
        for r in reloc.rewrites[:20]:
            w(f"    {r}\n")
        if len(reloc.rewrites) > 20:
            w(f"    ... {len(reloc.rewrites) - 20} more\n")

    if verbose:
        host = probe_host()
        w(f"\n  {_c('host runtime', DIM)}\n")
        for key, value in host.as_dict().items():
            w(f"    {key:<26} {value}\n")

    if a.findings:
        w("\n")
        for f in a.findings:
            colour = RED if f.severity is Severity.FATAL else YELLOW
            tag = "FATAL" if f.severity is Severity.FATAL else "warn "
            w(f"  {_c(tag, colour)} [{f.code}] {f.message}\n")
            if f.detail:
                for line in f.detail.splitlines():
                    w(f"        {_c(line.strip(), DIM)}\n")

    w("\n  ")
    if a.verdict is Verdict.REFUSE:
        w(_c("REFUSED", RED))
        # A refusal on maintainer scripts says nothing about whether the
        # dependencies would have resolved. Report both so the user can
        # see how close the package actually is.
        if res.checked and res.requires:
            if res.unsatisfied:
                w(_c(f"  (dependencies: {len(res.unsatisfied)} unsatisfied "
                     f"of {len(res.requires)})", DIM))
            else:
                w(_c(f"  (dependencies would have resolved: "
                     f"{len(res.requires)}/{len(res.requires)})", DIM))
    elif a.verdict is Verdict.UNKNOWN:
        w(_c("INDETERMINATE", YELLOW))
    elif a.verdict is Verdict.STRATEGY_A:
        w(_c("STRATEGY A", GREEN) + "  translate to RPM")
    else:
        w(_c("STRATEGY B", YELLOW) + "  private prefix under /opt/debfed")
    w(f"  {_c('- ' + a.reason, DIM)}\n\n")


def as_dict(an: Analysis) -> dict:
    return {
        "package": an.deb.name,
        "version": an.deb.version,
        "architecture": an.deb.architecture,
        "summary": an.deb.summary,
        "files": len(an.reloc.files),
        "rewrites": [str(r) for r in an.reloc.rewrites],
        "private_prefixes": an.reloc.private_prefixes,
        "setuid": an.reloc.setuid,
        "maintainer_scripts": list(an.deb.maintainer_scripts),
        "deb_depends": [str(d) for d in an.deb.depends],
        "rpm_requires": an.res.requires,
        "rpm_provides": an.res.provides,
        "satisfied": an.res.satisfied,
        "unsatisfied": an.res.unsatisfied,
        "self_satisfied": an.res.self_satisfied,
        "foreign_objects": an.res.foreign,
        "fedora_packages": an.res.fedora_packages,
        "mapped_extras": an.extra_requires,
        "unmapped": an.unmapped,
        "scriptlets_kept": an.scripts.translated,
        "scriptlets_stripped": an.scripts.stripped,
        "findings": [
            {"severity": f.severity.value, "code": f.code,
             "message": f.message, "detail": f.detail}
            for f in an.assessment.findings
        ],
        "host_runtime": probe_host().as_dict(),
        "verdict": an.assessment.verdict.value,
        "reason": an.assessment.reason,
    }


# ---------------------------------------------------------------- commands


def cmd_inspect(args: argparse.Namespace) -> int:
    results, worst = [], 0
    for deb_path in args.deb:
        with tempfile.TemporaryDirectory(prefix="debfed-") as tmpdir:
            try:
                an = analyse(deb_path, Path(tmpdir), offline=args.offline,
                             map_file=args.map_file,
                             strict_scripts=args.strict_scripts)
            except (DebError, UnsafeInput, ValueError) as exc:
                # The package itself is malformed or hostile: a verdict.
                print(f"error: {exc}", file=sys.stderr)
                worst = max(worst, 1)
                continue
            except ResolveError as exc:
                # Missing rpmdeps/dnf: we could not decide.
                print(f"error: {exc}", file=sys.stderr)
                worst = 2
                continue
            if args.json:
                results.append(as_dict(an))
            else:
                print_inspect(an, verbose=args.verbose)
            if an.assessment.verdict is Verdict.REFUSE:
                worst = max(worst, 1)
    if args.json:
        print(json.dumps(results, indent=2))
    return worst


def _bundle_for_strategy_b(an: Analysis) -> list[str]:
    """Copy unsatisfiable libraries into the private prefix and re-point
    the payload at them. Returns the files added, or raises if the
    bundle cannot be made to resolve."""
    plan = plan_bundle(an.deb.name, an.res.unsatisfied, an.reloc.buildroot,
                       extra_sources=[an.deb.payload_dir])
    if plan.unresolved:
        raise BundleError(
            "cannot bundle: no source for "
            + ", ".join(plan.unresolved[:4])
            + "\n  These are not libraries present in the package, so a "
            "private prefix cannot supply them."
        )
    added = apply_bundle(plan, an.reloc.buildroot)
    remaining = verify_bundle(plan, an.reloc.buildroot)
    if remaining:
        raise BundleError(
            "bundle did not resolve: " + ", ".join(remaining[:4])
            + "\n  Refusing rather than shipping a package that cannot start."
        )
    an.bundled_sonames = sorted(plan.sources)
    an.reloc.files.extend(added)
    an.reloc.files.sort()
    prefix = plan.prefix
    for d in (prefix, plan.libdir):
        if d not in an.reloc.dirs:
            an.reloc.dirs.append(d)
    an.reloc.dirs.sort()
    if prefix not in an.reloc.private_prefixes:
        an.reloc.private_prefixes.append(prefix)
    return added


def _build(an: Analysis, workdir: Path, quiet: bool):
    # UNKNOWN means dependency resolution was skipped (--offline), not
    # that bundling is needed. Treating it as B declares a private prefix
    # that nothing ever populates, and rpmbuild then fails on the missing
    # directory.
    strategy = ("A" if an.assessment.verdict in
                (Verdict.STRATEGY_A, Verdict.UNKNOWN) else "B")
    if strategy == "B":
        _bundle_for_strategy_b(an)
    plan = plan_spec(an.deb, an.reloc, an.scripts, strategy,
                     an.extra_requires, resolution=an.res)
    plan.bundled = sorted(an.bundled_sonames)
    spec_text = render(plan, an.reloc.buildroot)
    result = build_rpm(spec_text, an.reloc.buildroot, plan.name, workdir,
                       quiet=quiet)

    # The artifact is the only thing the user receives, so check it rather
    # than trusting that the analysis reached it.
    still_unsatisfiable = verify_requires(result.rpm_path,
                                          an.res.blocking_unsatisfied)
    if still_unsatisfiable:
        raise BundleError(
            "the built package still requires capabilities nothing provides:\n  "
            + "\n  ".join(still_unsatisfiable)
            + "\n\nThese are not in the payload, so a private prefix cannot "
            "supply them either. Refusing rather than handing over an rpm "
            "that dnf will reject."
        )
    return plan, spec_text, result


def cmd_build(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="debfed-") as tmpdir:
        tmp = Path(tmpdir)
        try:
            an = analyse(args.deb, tmp, offline=args.offline,
                         map_file=args.map_file,
                         strict_scripts=args.strict_scripts)
        except (DebError, UnsafeInput, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except ResolveError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if an.assessment.verdict is Verdict.REFUSE:
            print_inspect(an)
            print(f"{_c('refusing to build', RED)}: {an.assessment.reason}",
                  file=sys.stderr)
            return 1

        strategy = ("A" if an.assessment.verdict in
                    (Verdict.STRATEGY_A, Verdict.UNKNOWN) else "B")

        if args.spec_only:
            plan = plan_spec(an.deb, an.reloc, an.scripts, strategy,
                             an.extra_requires, resolution=an.res)
            sys.stdout.write(render(plan, an.reloc.buildroot))
            return 0

        try:
            # Must go through _build: it performs the Strategy B bundling
            # step. An earlier version of this function reimplemented the
            # pipeline inline and silently skipped it, so `build` produced
            # RPMs that required libraries nothing provides and still
            # exited 0.
            _plan, _spec_text, result = _build(an, tmp, quiet=not args.verbose)
        except UnsafeInput as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except BundleError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except BuildError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        dest = args.output or Path.cwd()
        dest.mkdir(parents=True, exist_ok=True)
        final = dest / result.rpm_path.name
        shutil.copy2(result.rpm_path, final)
        print(f"{_c('built', GREEN)}  {final}")
        return 0


def cmd_install(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="debfed-") as tmpdir:
        tmp = Path(tmpdir)
        try:
            an = analyse(args.deb, tmp, map_file=args.map_file,
                         strict_scripts=args.strict_scripts)
        except (DebError, UnsafeInput, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except ResolveError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        print_inspect(an, verbose=args.verbose)

        if an.assessment.verdict is Verdict.REFUSE:
            print(f"{_c('refusing to install', RED)}: {an.assessment.reason}",
                  file=sys.stderr)
            return 1

        conflicts = find_conflicts(an.reloc)
        if conflicts:
            print(f"  {_c('FILE CONFLICTS', RED)}\n")
            for c in conflicts[:15]:
                print(f"    {c.path}  {_c('owned by ' + c.owner, DIM)}")
            if len(conflicts) > 15:
                print(f"    ... {len(conflicts) - 15} more")
            print(f"\n  {len(conflicts)} file(s) already belong to installed "
                  "packages. Refusing.\n")
            return 1

        existing = rpm_query_installed(an.deb.name)
        if existing:
            print(f"  {_c('note', YELLOW)} {existing} is already installed; "
                  "this will upgrade or reinstall it.\n")

        try:
            _, _, result = _build(an, tmp, quiet=not args.verbose)
        except UnsafeInput as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except BundleError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except BuildError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        print(f"  {_c('built', GREEN)} {result.rpm_path.name}\n")

        print(f"  {_c('DRY RUN', BOLD)} - dnf transaction preview\n")
        dnf_install(result.rpm_path, assume_yes=False, test=True)

        if args.dry_run:
            print(f"\n  {_c('stopping here', DIM)} (--dry-run)\n")
            return 0

        if not args.yes:
            try:
                answer = input("\n  Proceed with install? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return 1
            if answer not in ("y", "yes"):
                print("  aborted\n")
                return 1

        return dnf_install(result.rpm_path, assume_yes=True)


def cmd_gui_install(args: argparse.Namespace) -> int:
    """Graphical flow, used when a package is opened from a file manager."""
    from .gui import install as gui_install

    return gui_install(args.deb, verbose=args.verbose)


def cmd_remove(args: argparse.Namespace) -> int:
    installed = rpm_query_installed(args.name)
    if not installed:
        print(f"error: {args.name} is not installed", file=sys.stderr)
        return 1
    print(f"  removing {installed} via dnf")
    return dnf_remove(args.name, assume_yes=args.yes)


def cmd_map(args: argparse.Namespace) -> int:
    if args.map_action == "list":
        db = mapdb.load(args.map_file)
        print(f"# mapping database v{db.version}")
        for src in db.sources or []:
            print(f"# source: {src}")
        for deb_name in sorted(db.packages):
            print(f"{deb_name}: {', '.join(db.packages[deb_name])}")
        for deb_name in sorted(db.ignore):
            print(f"{deb_name}: (ignored)")
        return 0

    if args.map_action == "get":
        db = mapdb.load(args.map_file)
        result = db.lookup(args.name)
        if result is None:
            print(f"{args.name}: not mapped")
            return 1
        print(f"{args.name}: {', '.join(result) if result else '(ignored)'}")
        return 0

    if args.map_action == "add":
        path = mapdb.add(args.name, args.fedora)
        print(f"added {args.name} -> {', '.join(args.fedora)}  ({path})")
        return 0

    if args.map_action == "remove":
        if mapdb.remove(args.name):
            print(f"removed {args.name}")
            return 0
        print(f"{args.name}: no user mapping to remove", file=sys.stderr)
        return 1

    return 2


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="debfed",
        description="Install Debian-targeted applications on Fedora as native RPMs.",
        epilog="debfed is not a general Debian-to-Fedora converter. It refuses "
               "base packages, kernel modules, and anything requiring dpkg "
               "semantics.",
    )
    p.add_argument("--version", action="version", version=f"debfed {__version__}")
    # Shared options live on a parent parser so they work either before or
    # after the subcommand. Declaring them only at the top level means
    # `debfed inspect --map-file X` is an argparse error, which is not what
    # anyone expects from a CLI.
    # default=SUPPRESS matters: without it the subparser writes its own
    # default over a value already parsed before the subcommand, so
    # `debfed --strict-scripts inspect x.deb` would silently lose the flag.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--map-file", type=Path, metavar="PATH",
                        default=argparse.SUPPRESS,
                        help="additional mapping database, highest precedence")
    common.add_argument("--strict-scripts", action="store_true",
                        default=argparse.SUPPRESS,
                        help="refuse packages whose maintainer scripts ask a "
                             "debconf question, instead of warning")

    p.add_argument("--map-file", type=Path, default=None,
                   help=argparse.SUPPRESS)
    p.add_argument("--strict-scripts", action="store_true", default=False,
                   help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)

    insp = sub.add_parser("inspect", parents=[common], help="report requirements, strategy, refusals")
    insp.add_argument("deb", type=Path, nargs="+")
    insp.add_argument("--json", action="store_true")
    insp.add_argument("-v", "--verbose", action="store_true")
    insp.add_argument("--offline", action="store_true",
                      help="skip dnf resolution; no strategy will be chosen")
    insp.set_defaults(func=cmd_inspect)

    bld = sub.add_parser("build", parents=[common], help="produce an RPM without installing it")
    bld.add_argument("deb", type=Path)
    bld.add_argument("-o", "--output", type=Path, metavar="DIR")
    bld.add_argument("--spec-only", action="store_true",
                     help="print the generated spec and exit")
    bld.add_argument("--offline", action="store_true",
                     help="skip dnf resolution (spec inspection only)")
    bld.add_argument("-v", "--verbose", action="store_true")
    bld.set_defaults(func=cmd_build)

    ins = sub.add_parser("install", parents=[common], help="convert and install (dry run first)")
    ins.add_argument("deb", type=Path)
    ins.add_argument("-y", "--yes", action="store_true",
                     help="skip the confirmation prompt (the dry run still runs)")
    ins.add_argument("--dry-run", action="store_true", help="stop after the dry run")
    ins.add_argument("-v", "--verbose", action="store_true")
    ins.set_defaults(func=cmd_install)

    gui = sub.add_parser(
        "gui-install", parents=[common],
        help="convert and install with a graphical prompt (used by the "
             "file-manager association)")
    gui.add_argument("deb", type=Path)
    gui.add_argument("-v", "--verbose", action="store_true")
    gui.set_defaults(func=cmd_gui_install)

    rm = sub.add_parser("remove", help="remove an installed package via dnf")
    rm.add_argument("name")
    rm.add_argument("-y", "--yes", action="store_true")
    rm.set_defaults(func=cmd_remove)

    mp = sub.add_parser("map", help="view and edit the dependency mapping database")
    msub = mp.add_subparsers(dest="map_action", required=True)
    msub.add_parser("list", help="print every mapping")
    g = msub.add_parser("get", help="look up one Debian package name")
    g.add_argument("name")
    a = msub.add_parser("add", help="add or replace a user mapping")
    a.add_argument("name")
    a.add_argument("fedora", nargs="+")
    r = msub.add_parser("remove", help="delete a user mapping")
    r.add_argument("name")
    mp.set_defaults(func=cmd_map)

    return p


def main(argv: list[str] | None = None) -> int:
    # Restore default SIGPIPE handling so `debfed map list | head` exits
    # quietly instead of raising BrokenPipeError.
    try:
        import signal

        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass

    args = build_parser().parse_args(argv)
    if not hasattr(args, "map_file"):
        args.map_file = None
    if not hasattr(args, "strict_scripts"):
        args.strict_scripts = False
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
