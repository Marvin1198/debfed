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
from .layout import UNOWNABLE_DIRS, Relocation
from .sanitize import (
    safe_name,
    safe_requires,
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
        return None, _INVALID_VERSION_CHARS.sub(".", deb_version), "1"
    epoch = m.group("epoch")
    version = _INVALID_VERSION_CHARS.sub(".", m.group("upstream"))
    revision = m.group("revision")
    release = _INVALID_VERSION_CHARS.sub(".", revision) if revision else "1"
    return epoch, version, release


def guess_license(deb: Deb) -> str:
    """Best-effort licence from the Debian copyright file.

    rpm requires a License tag. Guessing wrong is better than failing to
    build, but the value is reported so the user can correct it.
    """
    for candidate in deb.payload_dir.rglob("usr/share/doc/*/copyright"):
        try:
            text = candidate.read_text(errors="replace")
        except OSError:
            continue
        m = re.search(r"^License:\s*(.+)$", text, re.MULTILINE)
        if m:
            candidate = m.group(1).strip().split("\n")[0][:64]
            # Read out of the payload, so untrusted.
            if re.match(r"^[A-Za-z0-9][A-Za-z0-9+.\-\s()]*$", candidate):
                return candidate
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
) -> SpecPlan:
    plan = SpecPlan(
        deb=deb,
        reloc=reloc,
        scripts=scripts,
        strategy=strategy,
        extra_requires=sorted(set(extra_requires or [])),
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

    # --- scriptlets ------------------------------------------------------
    if plan.scripts.post:
        add("%post")
        for fragment in plan.scripts.post:
            add(fragment)
        add("")
    if plan.scripts.postun:
        add("%postun")
        for fragment in plan.scripts.postun:
            add(fragment)
        add("")

    # --- files -----------------------------------------------------------
    add("%files")
    conffiles = set(deb.conffiles)

    ownable = [d for d in reloc.dirs if d not in UNOWNABLE_DIRS]
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
