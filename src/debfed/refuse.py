"""The refusal engine.

debfed's value is as much in what it refuses as in what it installs. A
tool that half-installs a base package is worse than one that declines.
Every refusal names a specific reason; none of them are "unsupported".

Refusals run BEFORE any spec is rendered, so a rejected package never
reaches rpmbuild.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from .deb import Deb, parse_depends
from .depsolve import Resolution
from .layout import Relocation


class Verdict(StrEnum):
    STRATEGY_A = "A"          # translate to RPM, host libraries satisfy it
    STRATEGY_B = "B"          # private prefix, bundle leaf libraries
    UNKNOWN = "unknown"       # dependency resolution was not performed
    REFUSE = "refuse"


class Severity(StrEnum):
    FATAL = "fatal"
    WARN = "warn"


@dataclass(frozen=True)
class Finding:
    severity: Severity
    code: str
    message: str
    detail: str = ""

    def __str__(self) -> str:
        head = f"[{self.code}] {self.message}"
        return f"{head}\n    {self.detail}" if self.detail else head


# Packages that own the base system. Installing a Debian build of any of
# these over Fedora's copy is unrecoverable.
BASE_PACKAGES = frozenset(
    {
        "libc6", "libc6-dev", "libc-bin", "glibc", "locales",
        "systemd", "systemd-sysv", "libsystemd0", "udev",
        "dbus", "libdbus-1-3",
        "coreutils", "bash", "dash", "sed", "grep", "gawk", "tar", "gzip",
        "util-linux", "mount", "login", "passwd", "libpam0g",
        "dpkg", "apt", "perl-base",
        "libselinux1", "libgcc-s1", "libstdc++6",
        "e2fsprogs", "initramfs-tools",
        "grub-common", "grub-pc", "grub-efi-amd64", "shim-signed",
        "gdm3", "sddm", "lightdm", "xserver-xorg-core",
        "linux-image-generic", "linux-headers-generic",
    }
)

# Paths that belong to the boot chain or the kernel. Installing a Debian
# build of any of these is unrecoverable.
#
# NOTE: /usr/lib/systemd/system is NOT here. That is %{_unitdir} -- the
# directory Fedora packaging guidelines *require* unit files to be
# installed into. Treating it as a base path refused every package that
# ships a service file, which is normal, correct behaviour for a daemon.
BASE_PATH_PREFIXES = (
    "/boot/",
    "/usr/lib/modules/",
    "/lib/modules/",
    "/usr/lib/dracut/",
    "/usr/lib/kernel/",
    "/etc/grub.d/",
    "/usr/lib/grub/",
    "/usr/lib/systemd/systemd",      # the binary itself, not the unit dir
    "/usr/lib/systemd/system-generators/",
)

# Unit directories, handled with scriptlets rather than refused.
UNIT_DIRS = (
    "/usr/lib/systemd/system/",
    "/usr/lib/systemd/user/",
    "/etc/systemd/system/",
)

# Files that mean this package expects dpkg to be the package manager.
DPKG_ONLY_FILES = (
    "/var/lib/dpkg",
    "/etc/apt/sources.list.d",
    "/etc/apt/trusted.gpg.d",
    "/usr/share/dpkg",
)

# dpkg triggers that map cleanly onto an rpm scriptlet. `activate-noawait
# ldconfig` is added automatically by dh_makeshlibs to nearly every library
# package, so refusing on the presence of a triggers file alone rejects
# most of the archive for no reason. Value is the scriptlet we emit.
SAFE_TRIGGERS: dict[str, str] = {
    "ldconfig": "/sbin/ldconfig",
    "/usr/share/applications": "update-desktop-database &>/dev/null || :",
    "/usr/share/icons/hicolor": (
        "gtk-update-icon-cache -qtf /usr/share/icons/hicolor &>/dev/null || :"
    ),
    "/usr/share/mime": "update-mime-database /usr/share/mime &>/dev/null || :",
    "/usr/share/mime/packages": (
        "update-mime-database /usr/share/mime &>/dev/null || :"
    ),
    "/usr/share/glib-2.0/schemas": (
        "glib-compile-schemas /usr/share/glib-2.0/schemas &>/dev/null || :"
    ),
    "/usr/share/fonts": "fc-cache -f &>/dev/null || :",
    "/usr/share/man": ":",      # man-db indexes lazily on Fedora
    "man-db": ":",
    "/usr/share/doc": ":",
    "update-menus": ":",        # Debian menu system, no Fedora analogue needed
}

# debconf commands that actually prompt. Sourcing /usr/share/debconf/
# confmodule is inert on its own, and most db_* verbs only read or write
# the answer database:
#
#   db_get, db_set, db_fset, db_metaget, db_register, db_subst, db_purge,
#   db_version, db_capb, db_settitle, db_reset, db_stop
#
# never display anything. Only db_input queues a question and db_go
# displays the queue -- and even those fall back to stored defaults under
# the noninteractive frontend.
#
# Refusing a package merely for sourcing confmodule rejects a large class
# of working vendor packages. VS Code is the canonical example: every
# db_* call it makes governs one question -- whether to register the
# Microsoft apt repository -- which debfed strips anyway, and upstream
# ships an explicit code path for systems with no debconf at all.
DEBCONF_PROMPTING = re.compile(r"\bdb_(input|go|text)\b")
DEBCONF_ANY = re.compile(r"\bdb_[a-z]+\b|/usr/share/debconf/confmodule")
# A debconf template name is always owner/question, so requiring the slash
# is what keeps prose out of the result. Without it, VS Code's comment
# "even after db_get is called on a first install" yields a question named
# "called".
DEBCONF_TEMPLATE = re.compile(
    r"\bdb_input\s+(?:low|medium|high|critical)\s+([\w.+-]+/[\w./+-]+)"
    r"|\bdb_(?:get|set|fset|register|subst|metaget)\s+([\w.+-]+/[\w./+-]+)"
)


def debconf_templates(body: str) -> list[str]:
    """Template names referenced by a script, ignoring comments."""
    names: set[str] = set()
    for line in body.splitlines():
        code = line.split("#", 1)[0]
        for match in DEBCONF_TEMPLATE.finditer(code):
            name = match.group(1) or match.group(2)
            if name:
                names.add(name)
    return sorted(names)

# Maintainer-script constructs with no RPM equivalent.
SCRIPT_BLOCKERS = (
    (r"\bdpkg-divert\b", "DIVERT", "uses dpkg-divert; rpm has no file diversion"),
    (r"\bdpkg-trigger\b", "TRIGGER", "uses dpkg triggers"),
    (r"\bupdate-initramfs\b", "INITRAMFS", "rebuilds the initramfs"),
    (r"\bdkms\b", "DKMS", "builds a kernel module via DKMS"),
    (r"\bupdate-grub\b|\bgrub-mkconfig\b", "GRUB", "modifies the bootloader"),
    (r"\bsystemctl\s+(enable|start)\b", "SYSTEMD_UNIT",
     "enables or starts a systemd unit"),
    (r"\badduser\b|\buseradd\b", "USER", "creates a system user"),
)

# Constructs we allow and translate into scriptlets.
SCRIPT_ALLOWED = (
    r"\bldconfig\b",
    r"\bupdate-desktop-database\b",
    r"\bdesktop-file-install\b",
    r"\bgtk-update-icon-cache\b",
    r"\bupdate-mime-database\b",
    r"\bxdg-mime\b",
    r"\bxdg-icon-resource\b",
    r"\bupdate-alternatives\b",   # allowed only in the single-symlink case
    r"\bglib-compile-schemas\b",
    r"\bfc-cache\b",
    r"\bupdate-menus\b",
    r"\bapt-key\b",               # stripped, not executed
    r"\bapt\b",                   # repo registration, stripped
    r"\bset -e\b",
    r"\bexit 0\b",
)


@dataclass
class Assessment:
    verdict: Verdict
    findings: list[Finding]
    reason: str = ""

    @property
    def fatal(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.FATAL]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARN]

    @property
    def ok(self) -> bool:
        return self.verdict is not Verdict.REFUSE


def assess(
    deb: Deb,
    reloc: Relocation,
    res: Resolution,
    *,
    allow_private_prefix: bool = True,
    strict_scripts: bool = False,
) -> Assessment:
    """Decide whether and how this package can be installed."""
    findings: list[Finding] = []

    # ---- identity refusals -------------------------------------------
    if deb.name in BASE_PACKAGES:
        findings.append(
            Finding(
                Severity.FATAL, "BASE_PACKAGE",
                f"{deb.name} is a base system package",
                "Installing a Debian build over Fedora's copy is unrecoverable. "
                "This is out of scope by design.",
            )
        )

    arch = deb.architecture
    if arch not in ("amd64", "all"):
        findings.append(
            Finding(
                Severity.FATAL, "ARCH",
                f"architecture {arch} is not supported",
                "debfed v1 targets x86_64 only.",
            )
        )

    # Pre-Depends encodes dpkg unpack ordering. For a leaf application it
    # is almost always a formality -- dpkg, libc6, multiarch-support,
    # init-system-helpers -- and refusing on its presence rejects large,
    # perfectly convertible packages such as Chromium. It only matters
    # when the package pre-depends on something we would have to replace.
    # Pre-Depends is never fatal on its own. It states unpack ordering --
    # "dpkg must be configured before I unpack" -- which is universally
    # true on Debian and meaningless on Fedora. Depending ON a base
    # package says nothing about whether we would replace one; being a
    # base package is caught separately by BASE_PACKAGES.
    #
    # Refusing on its presence rejected Chromium (Pre-Depends: dpkg).
    pre_depends = parse_depends(deb.fields.get("Pre-Depends", ""))
    if pre_depends:
        findings.append(
            Finding(
                Severity.WARN, "PRE_DEPENDS",
                f"package declares Pre-Depends ({len(pre_depends)})",
                ", ".join(d.name for d in pre_depends[:6])
                + "\n    dpkg unpack ordering has no rpm analogue; for a leaf "
                "application this is normally a formality.",
            )
        )

    # ---- payload refusals --------------------------------------------
    for f in reloc.files:
        if any(f.startswith(p) for p in BASE_PATH_PREFIXES):
            findings.append(
                Finding(
                    Severity.FATAL, "SYSTEM_PATH",
                    "package writes into a boot or kernel path",
                    f,
                )
            )
            break

    for f in reloc.files:
        if any(f.startswith(p) for p in DPKG_ONLY_FILES):
            findings.append(
                Finding(
                    Severity.FATAL, "DPKG_STATE",
                    "package writes into dpkg or apt state directories",
                    f,
                )
            )
            break

    unsafe_triggers = [
        f"{directive} {target}"
        for directive, target in deb.triggers
        if target not in SAFE_TRIGGERS
    ]
    if unsafe_triggers:
        # debfed never runs maintainer scripts, so an unrecognised trigger
        # means one refresh action does not happen -- an icon cache, a
        # certificate bundle. That is a degradation, not a hazard, and
        # refusing on it rejects ordinary packages such as ca-certificates
        # and cups.
        findings.append(
            Finding(
                Severity.FATAL if strict_scripts else Severity.WARN,
                "TRIGGERS",
                f"{len(unsafe_triggers)} dpkg trigger(s) have no rpm equivalent",
                ", ".join(unsafe_triggers[:6])
                + "\n    These refresh actions will not run. Re-run the "
                "equivalent command by hand if the package depends on it.",
            )
        )

    # ---- debconf -----------------------------------------------------
    for script_name, body in deb.maintainer_scripts.items():
        if not DEBCONF_ANY.search(body):
            continue
        prompts = any(
            DEBCONF_PROMPTING.search(line.split("#", 1)[0])
            for line in body.splitlines()
        )
        templates = debconf_templates(body)
        shown = ", ".join(templates[:4]) if templates else "unnamed"
        if prompts:
            findings.append(
                Finding(
                    Severity.FATAL if strict_scripts else Severity.WARN,
                    "DEBCONF_PROMPT",
                    f"{script_name}: asks a configuration question during install",
                    f"question(s): {shown}\n"
                    "debfed does not run maintainer scripts, so the package's "
                    "default answer applies -- the same outcome as installing "
                    "with DEBIAN_FRONTEND=noninteractive. Check the question "
                    "above if the default matters to you.",
                )
            )
        else:
            findings.append(
                Finding(
                    Severity.WARN, "DEBCONF_READ",
                    f"{script_name}: reads the debconf database but never prompts",
                    f"key(s): {shown}\n"
                    "No question is displayed; only stored answers are read. "
                    "Nothing is lost by not running this.",
                )
            )

    # ---- maintainer scripts ------------------------------------------
    for script_name, body in deb.maintainer_scripts.items():
        for pattern, code, message in SCRIPT_BLOCKERS:
            if re.search(pattern, body):
                severity = (
                    Severity.WARN
                    if code in ("USER", "SYSTEMD_UNIT", "TRIGGER")
                    else Severity.FATAL
                )
                findings.append(
                    Finding(severity, code, f"{script_name}: {message}")
                )

    # ---- dependency verdict ------------------------------------------
    # Version skew is a property of the binaries and the running host, so
    # it is checked directly rather than inferred from what dnf could not
    # satisfy. Otherwise --offline silently accepts packages that can
    # never run: audacity requiring GLIBC_2.43 on a 2.39 host built fine
    # and then failed at exec.
    skew = res.glibc_skew
    if skew:
        required, host = skew
        req_s = ".".join(str(x) for x in required)
        host_s = ".".join(str(x) for x in host)
        findings.append(
            Finding(
                Severity.FATAL, "GLIBC_SKEW",
                f"payload needs glibc {req_s}; this host has {host_s}",
                "Forward compatibility does not work in this direction. "
                "Bundling glibc would require shipping a matching ld.so, "
                "which is out of scope. Use a newer Fedora, or a container.",
            )
        )
    elif res.needs_newer_glibc:
        findings.append(
            Finding(
                Severity.FATAL, "GLIBC_SKEW",
                "payload needs a newer glibc than this host provides",
                f"{res.needs_newer_glibc} is unsatisfiable.",
            )
        )

    toolkit_gap = res.missing_toolkit
    if toolkit_gap:
        findings.append(
            Finding(
                Severity.FATAL, "TOOLKIT_GAP",
                "payload would require bundling a toolkit stack",
                ", ".join(toolkit_gap[:6])
                + "\n    Prefixing LD_LIBRARY_PATH breaks as soon as the app "
                "dlopens a host module (mesa, GTK modules, NSS).",
            )
        )

    symver = res.symbol_version_only
    cosmetic_symver = set(res.cosmetic_version_misses)
    if symver:
        findings.append(
            Finding(
                Severity.WARN, "SYMBOL_VERSION",
                f"{len(symver)} capability/capabilities differ only by symbol version",
                ", ".join(symver[:4])
                + (f"\n    {len(cosmetic_symver)} of these are cosmetic: the "
                   "provider defines no symbol versions at all, so the dynamic "
                   "linker warns and continues (glibc dl-version.c). No "
                   "bundling needed."
                   if cosmetic_symver else "")
                + "\n    The library itself resolves; only a distribution-specific "
                "symbol label is absent. Debian adds its own symbol versions to "
                "some libraries whose ABI is unchanged -- libcurl is the known "
                "case, where upstream exports unversioned symbols and Debian "
                "added CURL_OPENSSL_4. Bundling fixes it; the application would "
                "very likely have run without.",
            )
        )

    setuid_paths = reloc.setuid or deb.payload_setuid
    if setuid_paths:
        findings.append(
            Finding(
                Severity.WARN, "SETUID",
                "payload declares setuid/setgid files; the bits were dropped",
                ", ".join(setuid_paths[:8])
                + "\n    debfed extracts with tarfile's data filter, which clears "
                "these bits. An app relying on a SUID helper (a legacy "
                "chrome-sandbox, for example) will need user namespaces instead.",
            )
        )

    unowned = [d for d in reloc.dirs if d in __import__(
        "debfed.layout", fromlist=["UNOWNABLE_DIRS"]
    ).UNOWNABLE_DIRS]
    if unowned:
        findings.append(
            Finding(
                Severity.WARN, "SHARED_DIRS",
                f"{len(unowned)} directories are owned by Fedora base packages",
                "These will be excluded from %files (this is what makes alien "
                "output uninstallable).",
            )
        )

    if deb.conffiles:
        findings.append(
            Finding(
                Severity.WARN, "CONFFILES",
                f"{len(deb.conffiles)} conffiles will become %config(noreplace)",
            )
        )

    # ---- verdict -----------------------------------------------------
    fatal = [f for f in findings if f.severity is Severity.FATAL]
    if fatal:
        return Assessment(Verdict.REFUSE, findings, fatal[0].message)

    if not res.checked:
        return Assessment(
            Verdict.UNKNOWN, findings,
            f"{len(res.requires)} capabilities extracted; dnf resolution "
            "skipped, so no strategy can be chosen",
        )

    if not res.requires:
        return Assessment(
            Verdict.STRATEGY_A, findings, "no ELF payload; pure data package"
        )

    blocking = res.blocking_unsatisfied
    cosmetic = res.cosmetic_version_misses

    if not blocking:
        reason = f"all {len(res.requires)} requirements resolve against Fedora"
        if cosmetic:
            reason += (f" ({len(cosmetic)} symbol-version label(s) absent; the "
                       "linker only warns)")
        return Assessment(Verdict.STRATEGY_A, findings, reason)

    if not allow_private_prefix:
        findings.append(
            Finding(
                Severity.FATAL, "UNSATISFIED",
                f"{len(blocking)} requirements unsatisfied and "
                "private-prefix fallback is disabled",
                ", ".join(blocking[:6]),
            )
        )
        return Assessment(Verdict.REFUSE, findings, "unsatisfied dependencies")

    return Assessment(
        Verdict.STRATEGY_B, findings,
        f"{len(blocking)} leaf library/libraries must be bundled",
    )
