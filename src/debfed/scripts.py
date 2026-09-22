"""Maintainer script translation.

Debian maintainer scripts assume dpkg, update-alternatives, and a pile of
Debian helper binaries. We do not execute them. We parse them, keep only
the constructs that have an exact Fedora equivalent, and log everything
dropped so the user can see what was skipped rather than discovering it
at runtime.

Vendor packages in particular use postinst almost exclusively to register
an apt repository and install a signing key. On Fedora that is not merely
useless, it is wrong, so it is always stripped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# (pattern, rpm scriptlet fragment, human label)
TRANSLATIONS: tuple[tuple[str, str, str], ...] = (
    (r"\bldconfig\b", "/sbin/ldconfig", "refresh linker cache"),
    (
        r"\bupdate-desktop-database\b",
        "update-desktop-database &>/dev/null || :",
        "refresh desktop database",
    ),
    (
        r"\bgtk-update-icon-cache\b|\bxdg-icon-resource\b",
        "gtk-update-icon-cache -qtf /usr/share/icons/hicolor &>/dev/null || :",
        "refresh icon cache",
    ),
    (
        r"\bupdate-mime-database\b|\bxdg-mime\b",
        "update-mime-database /usr/share/mime &>/dev/null || :",
        "refresh mime database",
    ),
    (
        r"\bglib-compile-schemas\b",
        "glib-compile-schemas /usr/share/glib-2.0/schemas &>/dev/null || :",
        "compile gsettings schemas",
    ),
    (r"\bfc-cache\b", "fc-cache -f &>/dev/null || :", "refresh font cache"),
)

# Constructs that are deliberately discarded rather than translated.
STRIPPED: tuple[tuple[str, str], ...] = (
    (r"apt-key|/etc/apt/trusted\.gpg|gpg --dearmor", "apt signing key registration"),
    (r"/etc/apt/sources\.list|add-apt-repository", "apt repository registration"),
    (r"/etc/apparmor\.d|apparmor_parser|aa-enforce", "AppArmor profile (Fedora uses SELinux)"),
    (r"\bupdate-menus\b|/usr/share/menu/", "Debian menu system"),
    (r"\bdh_\w+", "debhelper snippet"),
    (r"\bdpkg-maintscript-helper\b", "dpkg maintscript helper"),
    (r"\bupdate-alternatives\b", "update-alternatives (no Fedora equivalent)"),
    (r"\binstall-info\b", "GNU info directory update"),
    (r"\bsystemd-tmpfiles\b", "tmpfiles replay (rpm does this itself)"),
)


@dataclass
class ScriptPlan:
    """What we will run, and what we deliberately will not."""

    post: list[str] = field(default_factory=list)
    postun: list[str] = field(default_factory=list)
    posttrans: list[str] = field(default_factory=list)
    translated: list[str] = field(default_factory=list)
    stripped: list[str] = field(default_factory=list)
    unrecognised: list[str] = field(default_factory=list)

    def add_post(self, fragment: str) -> None:
        if fragment not in self.post:
            self.post.append(fragment)

    def add_postun(self, fragment: str) -> None:
        if fragment not in self.postun:
            self.postun.append(fragment)


# Many vendor packages do not ship their PATH entry. They create it in
# postinst with `ln -s` or update-alternatives, because on Debian the
# maintainer script is the normal place to do it. debfed never runs those
# scripts, so without translating them the application installs correctly
# and is then not on PATH -- which looks like a broken conversion.
#
# rpm's equivalent is simply to ship the symlink in %files, where it is
# owned and removed with the package.
_LN_RE = re.compile(
    r"^\s*ln\s+(?:-[a-zA-Z]+\s+)*(?P<target>/[^\s;|&]+)\s+(?P<link>/[^\s;|&]+)",
    re.MULTILINE,
)
_ALTERNATIVES_RE = re.compile(
    r"update-alternatives\s+--install\s+(?P<link>/[^\s]+)\s+\S+\s+"
    r"(?P<target>/[^\s]+)",
    re.MULTILINE,
)

# Where a package may legitimately place a launcher.
LAUNCHER_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/")


def extract_symlinks(scripts: dict[str, str],
                     package: str = "") -> list[tuple[str, str]]:
    """Symlinks a maintainer script would have created, as (link, target).

    Only an application's *own* launcher is restored. A generic
    alternatives slot such as /usr/bin/editor -> /usr/bin/codium is
    deliberately skipped: that is a shared name arbitrated by
    update-alternatives on Debian, and claiming ownership of it in an
    rpm would collide with whatever else provides it.

    The test is that the link and its target share a basename, or the
    link is named after the package. Everything else is left alone --
    this restores a PATH entry, it does not replay arbitrary filesystem
    operations from an untrusted script.
    """
    found: dict[str, str] = {}
    for name, body in scripts.items():
        if name not in ("postinst", "preinst"):
            continue
        code = "\n".join(line.split("#", 1)[0] for line in body.splitlines())
        for match in list(_LN_RE.finditer(code)) + list(
                _ALTERNATIVES_RE.finditer(code)):
            link = match.group("link")
            target = match.group("target")
            if not link.startswith(LAUNCHER_DIRS):
                continue
            if ".." in link or ".." in target:
                continue
            link_name = link.rsplit("/", 1)[1]
            target_name = target.rsplit("/", 1)[1]
            if link_name != target_name and link_name != package:
                continue          # a shared alternatives slot, not our launcher
            found.setdefault(link, target)
    return sorted(found.items())


_NOISE = re.compile(
    r"^\s*(#|set\s|if\s|fi\b|then\b|else\b|elif\s|case\s|esac\b|;;|\}|\{"
    r"|for\s|done\b|do\b|while\s|exit\b|return\b|true\b|:\s*$|\[|\]|\)\s*$)"
)


def analyse_scripts(
    scripts: dict[str, str], triggers: list[tuple[str, str]],
    safe_triggers: dict[str, str],
) -> ScriptPlan:
    """Turn Debian maintainer scripts + triggers into an rpm scriptlet plan."""
    plan = ScriptPlan()

    for _directive, target in triggers:
        fragment = safe_triggers.get(target)
        if fragment and fragment != ":":
            plan.add_post(fragment)
            if fragment == "/sbin/ldconfig":
                plan.add_postun(fragment)
            plan.translated.append(f"trigger {target} -> {fragment}")

    for name, body in scripts.items():
        is_removal = name in ("prerm", "postrm")

        for pattern, fragment, label in TRANSLATIONS:
            if re.search(pattern, body):
                if is_removal:
                    plan.add_postun(fragment)
                else:
                    plan.add_post(fragment)
                plan.translated.append(f"{name}: {label}")

        for pattern, label in STRIPPED:
            if re.search(pattern, body):
                plan.stripped.append(f"{name}: {label}")

        for line in body.splitlines():
            stripped_line = line.strip()
            if not stripped_line or _NOISE.match(stripped_line):
                continue
            known = any(re.search(p, stripped_line) for p, _, _ in TRANSLATIONS)
            known = known or any(re.search(p, stripped_line) for p, _ in STRIPPED)
            if not known:
                plan.unrecognised.append(f"{name}: {stripped_line[:100]}")

    # ldconfig is cheap and always correct for a package shipping libraries
    return plan



# A launcher that downloads the real application at first run, rather
# than shipping it. Discord is the archetype: /usr/bin/discord is a
# shell script that fetches roughly 100MB into $XDG_CONFIG_HOME and
# executes that, so the package holds a few megabytes of bootstrapper
# and the application itself never passes through rpm at all.
#
# This matters to whoever installs it. rpm cannot verify the running
# binary, removing the package leaves the downloaded copy behind in the
# user's home directory, and the application updates itself without dnf
# ever knowing. None of that is debfed's doing and none of it can be
# fixed from here -- but it should not be a surprise.
_DOWNLOAD_URL = re.compile(r'https?://[^\s"\';|)]+', re.IGNORECASE)
_FETCHER = re.compile(r"\b(curl|wget|aria2c|fetch)\b")
_USER_DIR = re.compile(r"\$(XDG_CONFIG_HOME|XDG_DATA_HOME|HOME)\b")

# Launchers are small. Anything larger is a real program.
_MAX_LAUNCHER_BYTES = 64 * 1024


def detect_bootstrapper(files: dict[str, bytes]) -> tuple[str, str] | None:
    """(path, url) when a shipped launcher downloads the application.

    `files` maps installed paths to their contents. Only executable
    scripts in launcher directories are considered: a URL inside
    documentation or a sample configuration means nothing.
    """
    for path, blob in sorted(files.items()):
        if not path.startswith(LAUNCHER_DIRS):
            continue
        if len(blob) > _MAX_LAUNCHER_BYTES or not blob.startswith(b"#!"):
            continue
        body = blob.decode("utf-8", "replace")
        code = "\n".join(line.split("#", 1)[0] for line in body.splitlines())
        match = _DOWNLOAD_URL.search(code)
        if match is None:
            continue
        if not _FETCHER.search(code) and "DOWNLOAD" not in body:
            continue
        if not _USER_DIR.search(code):
            continue
        return path, match.group(0)
    return None
