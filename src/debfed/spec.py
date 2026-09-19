"""RPM spec generation.

Three things here are load-bearing and easy to get wrong:

1. %files must never claim a directory owned by Fedora's `filesystem`
   package. Claiming /usr/bin is what makes `alien` output refuse to
   install.

2. Provides must be filtered for any private prefix. An Electron app
   bundles libffmpeg.so, libEGL.so and friends; without filtering the
   generated RPM advertises those to the whole system and dnf may
   satisfy unrelated packages from inside your app.

3. rpm's binary post-processing must be disabled. brp-strip will strip
   vendor binaries, brp-mangle-shebangs will rewrite interpreters, and
   debuginfo extraction will fail or corrupt prebuilt payloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .deb import Deb
from .depsolve import Resolution
from .layout import UNOWNABLE_DIRS, Relocation
from .sanitize import (
    safe_name,
    safe_requires,
    safe_version,
    spec_path,
    spec_text,
    spec_url,
    spec_value,
)
from .scripts import ScriptPlan

VENDOR_PREFIX = "/opt/debfed"

# Debian epoch:upstream-revision -> rpm Epoch/Version/Release
_VERSION_RE = re.compile(
    r"^(?:(?P<epoch>\d+):)?(?P<upstream>[^-]+)(?:-(?P<revision>.+))?$"
)

_INVALID_VERSION_CHARS = re.compile(r"[^A-Za-z0-9._+~^]")


def split_version(deb_version: str) -> tuple[str | None, str, str]:
    """Split a Debian version into (epoch, version, release).

    rpm forbids '-' in Version and Release, so the Debian revision moves
    into Release and anything else illegal is replaced with '.'.
    """
    m = _VERSION_RE.match(deb_version.strip())
    if not m:
        return None, safe_version(_INVALID_VERSION_CHARS.sub(".", deb_version)), "1"
    epoch = m.group("epoch")
    version = _INVALID_VERSION_CHARS.sub(".", m.group("upstream"))
    revision = m.group("revision")
    release = _INVALID_VERSION_CHARS.sub(".", revision) if revision else "1"
    return safe_version(epoch) if epoch else None, safe_version(version), \
        safe_version(release)


def guess_license(deb: Deb) -> str:
    """Best-effort licence from the Debian copyright file.

    rpm requires a License tag. Guessing wrong is better than failing to
    build, but the value is reported so the user can correct it.
    """
    for copyright_file in deb.payload_dir.rglob("usr/share/doc/*/copyright"):
        try:
            text = copyright_file.read_text(errors="replace")
        except OSError:
            continue
        m = re.search(r"^License:\s*(.+)$", text, re.MULTILINE)
        if m:
            declared = m.group(1).strip().split("\n")[0][:64]
            # Read out of the payload, so untrusted.
            if re.match(r"^[A-Za-z0-9][A-Za-z0-9+.\-\s()]*$", declared):
                return declared
        for token in ("GPL-3", "GPL-2", "LGPL-3", "LGPL-2", "MIT", "BSD-3",
                      "BSD-2", "Apache-2.0", "MPL-2.0", "ISC"):
            if token in text:
                return token
    return "Redistributable, no modification permitted"


def rpm_name(deb_name: str) -> str:
    """Validate a Debian package name for use as an rpm Name.

    Raises UnsafeInput rather than sanitising: the name also determines
    the spec filename on disk, so a traversal sequence here is an
    arbitrary file write, not a cosmetic problem.
    """
    return safe_name(deb_name)


@dataclass
class SpecPlan:
    """Everything needed to render a spec, decided before any text is emitted."""

    deb: Deb
    reloc: Relocation
    scripts: ScriptPlan
    strategy: str                     # "A" or "B"
    extra_requires: list[str] = field(default_factory=list)
    resolution: Resolution | None = None
    bundled: list[str] = field(default_factory=list)
    license: str = "Unspecified"
    vendor_prefix: str | None = None
    excluded_dirs: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return rpm_name(self.deb.name)

    @property
    def evr(self) -> tuple[str | None, str, str]:
        return split_version(self.deb.version)


def plan_spec(
    deb: Deb,
    reloc: Relocation,
    scripts: ScriptPlan,
    strategy: str,
    extra_requires: list[str] | None = None,
    resolution: Resolution | None = None,
) -> SpecPlan:
    """Plan the spec.

    `resolution` is not optional in spirit. rpmbuild runs its own
    dependency generator over the buildroot and knows nothing about the
    analysis, so without it the generated package requires every
    capability the analysis already established is bogus -- foreign
    architectures, libraries the payload ships itself, symbol labels the
    linker does not enforce. The verdict then says the package converts
    cleanly while dnf refuses to install it.
    """
    plan = SpecPlan(
        deb=deb,
        reloc=reloc,
        scripts=scripts,
        strategy=strategy,
        extra_requires=sorted(set(extra_requires or [])),
        resolution=resolution,
        license=guess_license(deb),
    )
    if strategy == "B":
        plan.vendor_prefix = f"{VENDOR_PREFIX}/{deb.name}"
    plan.excluded_dirs = [d for d in reloc.dirs if d in UNOWNABLE_DIRS]
    return plan


# ----------------------------------------------------------------- rendering


def _quote(path: str) -> str:
    """Escape and quote a %files entry.

    Delegates to spec_path, which refuses anything that cannot be
    represented safely rather than silently mangling it.
    """
    return spec_path(path)


def _filter_regex(prefixes: list[str]) -> str:
    if not prefixes:
        return ""
    alternatives = "|".join(re.escape(p) for p in prefixes)
    return f"^({alternatives})/.*$"


def _cap_pattern(capability: str) -> str:
    """A paren-free regex matching one rpm capability.

    Parentheses cannot be used. rpm expands these macros before handing
    them to regcomp, and escaped parens do not survive: an exclusion
    written as ^libfoo\\.so\\.1\\(\\)\\(64bit\\)$ silently fails to match,
    while the same pattern without parens works. Measured against
    rpmbuild directly.

    So the soname is escaped and the bracketed parts are matched with
    '.' wildcards instead.
    """
    soname, _, rest = capability.partition("(")
    pattern = re.escape(soname).replace("\\", "\\")
    if not rest:
        return "^" + pattern + "$"
    # libfoo.so.1(SYMVER)(64bit) -> ^libfoo\.so\.1.SYMVER.*$
    inner = rest.split(")", 1)[0]
    if inner:
        return "^" + pattern + "." + re.escape(inner) + ".*$"
    return "^" + pattern + "..*$"


def _requires_exclusions(plan: SpecPlan) -> tuple[str, str]:
    """(path regex, capability regex) for rpm's requires generator.

    rpm supports excluding by the file being scanned
    (__requires_exclude_from) and by the generated capability string
    (__requires_exclude). The analysis already knows which of each are
    spurious; this is how that knowledge reaches the package.

    Both regexes use top-level alternation (^a$|^b$) rather than a group
    (^(a|b)$), because parentheses do not survive macro expansion.
    """
    res = plan.resolution
    if res is None:
        return "", ""

    buildroot = str(plan.reloc.buildroot)
    paths: list[str] = []
    # Binaries for other architectures. Scanning them yields loaders no
    # host of this architecture can provide: ld-linux-aarch64.so.1,
    # ld-linux-armhf.so.3, ld64.so.2, plus their own glibc namespaces.
    for files in (res.foreign or {}).values():
        for f in files:
            installed = f[len(buildroot):] if f.startswith(buildroot) else f
            paths.append(re.escape(installed))
    if plan.vendor_prefix:
        paths.append(re.escape(plan.vendor_prefix) + "/lib/.*")

    caps: list[str] = []
    # Libraries the payload ships itself. rpm resolves these internally,
    # but only if it is not also told to require them from outside.
    caps.extend(_cap_pattern(c) for c in res.self_satisfied)
    # Symbol labels the dynamic linker does not enforce, because the
    # provider defines no versions at all. Only the versioned form is
    # excluded; the bare soname requirement stays so dnf still pulls the
    # library in.
    caps.extend(_cap_pattern(c) for c in res.cosmetic_version_misses)

    path_re = "|".join("^" + p + "$" for p in paths) if paths else ""
    cap_re = "|".join(caps) if caps else ""
    return path_re, cap_re


def render(plan: SpecPlan, payload_dir: Path) -> str:
    epoch, version, release = plan.evr
    deb, reloc = plan.deb, plan.reloc

    lines: list[str] = []
    add = lines.append

    add(f"# Generated by debfed from {deb.path.name}")
    add("# Do not edit by hand; regenerate with `debfed build`.")
    add("")

    # --- disable rpm's binary post-processing -------------------------
    add("# Payload is prebuilt third-party binaries. rpm must not strip,")
    add("# rewrite shebangs, or attempt debuginfo extraction on them.")
    add("%global debug_package %{nil}")
    add("%global __brp_strip %{nil}")
    add("%global __brp_strip_static_archive %{nil}")
    add("%global __brp_strip_comment_note %{nil}")
    add("%global __brp_mangle_shebangs %{nil}")
    add("%global __brp_check_rpaths %{nil}")
    add("%global _build_id_links none")
    add("%global _enable_debug_packages 0")
    add("")

    # --- provides / requires filtering --------------------------------
    filter_prefixes = list(reloc.private_prefixes)
    if plan.vendor_prefix:
        filter_prefixes = [plan.vendor_prefix]

    req_paths, req_caps = _requires_exclusions(plan)
    if req_paths:
        add("# Binaries for other architectures: their loaders and glibc")
        add("# namespaces can never be satisfied on this one.")
        add(f"%global __requires_exclude_from {req_paths}")
    if req_caps:
        add("# Capabilities the payload supplies itself, and symbol labels")
        add("# the dynamic linker does not enforce.")
        add(f"%global __requires_exclude {req_caps}")
    if req_paths or req_caps:
        add("")

    if filter_prefixes:
        regex = _filter_regex(filter_prefixes)
        add("# Bundled libraries must not advertise themselves system-wide,")
        add("# or dnf may satisfy unrelated packages from inside this app.")
        add(f"%global __provides_exclude_from {regex}")
        if plan.strategy == "B":
            add("# Strategy B ships its own copies; do not require them from the host.")
            add(f"%global __requires_exclude_from {regex}")
        add("")

    # --- header --------------------------------------------------------
    add(f"Name:           {plan.name}")
    if epoch:
        add(f"Epoch:          {epoch}")
    add(f"Version:        {version}")
    add(f"Release:        {release}%{{?dist}}")
    add(f"Summary:        {spec_value(deb.summary or plan.name)}")
    add(f"License:        {spec_value(plan.license, limit=80)}")
    homepage = spec_url(deb.homepage)
    if homepage:
        add(f"URL:            {homepage}")
    add("BuildArch:      x86_64")
    add("")
    add("# Converted from a Debian package; there is no buildable source.")
    add("Source0:        %{name}-%{version}.payload.tar")
    add("")

    safe_reqs = [r for r in (safe_requires(x) for x in plan.extra_requires) if r]
    for req in safe_reqs:
        add(f"Requires:       {req}")
    if safe_reqs:
        add("")

    if plan.vendor_prefix:
        add(f"# Strategy B: self-contained under {plan.vendor_prefix}")
        # Fedora's bundled software policy: a package carrying bundled
        # libraries must declare each one, so the distribution can find
        # every copy when the library has a security fix.
        add("#")
        add("# Fedora bundled software policy requires each bundled library")
        add("# to be declared, so a security fix can be traced to every copy.")
        for soname in sorted(plan.bundled):
            name = soname.split(".so")[0]
            add(f"Provides:       bundled({spec_value(name, limit=80)})")
        if not plan.bundled:
            add("Provides:       bundled(debfed-prefix) = %{version}")
        add("")

    add("%description")
    body = spec_text(deb.description or deb.summary or plan.name)
    for line in body.splitlines():
        add(line)
    add("")
    add(f"Converted from {spec_value(deb.path.name, limit=120)} by debfed.")
    add("")

    # --- build stages ---------------------------------------------------
    add("%prep")
    add("# nothing to prepare: payload is prebuilt")
    add("")
    add("%build")
    add("# nothing to build")
    add("")
    add("%install")
    add("rm -rf %{buildroot}")
    add("mkdir -p %{buildroot}")
    add("cp -a %{debfed_payload}/. %{buildroot}/")
    add("")

    # --- systemd units ----------------------------------------------------
    # /usr/lib/systemd/system is %{_unitdir}: shipping a unit there is the
    # documented, correct thing for an rpm to do. systemd still has to be
    # told the unit exists, so emit the lifecycle scriptlets.
    #
    # Units are deliberately NOT enabled. Fedora's preset policy governs
    # what starts by default, and a converted third-party package has no
    # business opting itself in.
    units = sorted(
        f.rsplit("/", 1)[1]
        for f in reloc.files
        if (f.startswith("/usr/lib/systemd/system/")
            or f.startswith("/usr/lib/systemd/user/"))
        and f.rsplit(".", 1)[-1] in
            ("service", "socket", "timer", "target", "path", "mount")
    )
    if units:
        add("# Unit files shipped; registered but deliberately not enabled.")
        add("%post")
        add("systemctl daemon-reload >/dev/null 2>&1 || :")
        add("")
        add("%preun")
        add("if [ $1 -eq 0 ]; then")
        for unit in units:
            add(f"  systemctl --no-reload disable --now {unit} >/dev/null 2>&1 || :")
        add("fi")
        add("")
        add("%postun")
        add("systemctl daemon-reload >/dev/null 2>&1 || :")
        add("")

    # --- scriptlets ------------------------------------------------------
    if plan.scripts.post and not units:
        add("%post")
        for fragment in plan.scripts.post:
            add(fragment)
        add("")
    if plan.scripts.postun and not units:
        add("%postun")
        for fragment in plan.scripts.postun:
            add(fragment)
        add("")

    # --- files -----------------------------------------------------------
    add("%files")
    conffiles = set(deb.conffiles)

    # Own only directories inside this package's own tree. Anything shared
    # is left unowned: claiming it is what makes alien output conflict with
    # filesystem, systemd, glibc-langpack and friends.
    ownable = reloc.ownable_dirs
    # Own only the topmost of each private tree; rpm takes the rest via %dir
    tops: list[str] = []
    for d in sorted(ownable):
        if not any(d.startswith(t + "/") for t in tops):
            tops.append(d)
    for d in tops:
        add(f"%dir {_quote(d)}")

    for d in sorted(set(ownable) - set(tops)):
        add(f"%dir {_quote(d)}")

    for f in reloc.files:
        if f in conffiles or f.startswith("/etc/"):
            add(f"%config(noreplace) {_quote(f)}")
        elif f.startswith("/usr/share/man/"):
            add(f"%doc {_quote(f)}")
        elif f.startswith("/usr/share/doc/"):
            add(f"%doc {_quote(f)}")
        else:
            add(_quote(f))

    for link in sorted(reloc.symlinks):
        add(_quote(link))

    add("")
    add("%changelog")
    stamp = datetime.now(UTC).strftime("%a %b %d %Y")
    add(f"* {stamp} debfed <debfed@localhost> - {version}-{release}")
    add(f"- Automated conversion of {spec_value(deb.path.name, limit=120)}")
    add("")

    return "\n".join(lines) + "\n"
