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
