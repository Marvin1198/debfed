"""Debian -> Fedora filesystem layout translation.

Debian uses multiarch paths (/usr/lib/x86_64-linux-gnu). Fedora uses the
biarch split (/usr/lib64). Debian has no /usr/lib64 and never will, so
the rewrite is one-way and unambiguous.

Both distributions are usr-merged, so /bin, /lib, /sbin are symlinks to
their /usr counterparts on both sides; we normalise into /usr anyway so
the generated RPM never owns a symlinked top-level directory.
"""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

# Longest prefix first. Applied to payload-relative paths (no leading /).
REWRITES: tuple[tuple[str, str], ...] = (
    ("usr/lib/x86_64-linux-gnu", "usr/lib64"),
    ("usr/libexec/x86_64-linux-gnu", "usr/libexec"),
    ("lib/x86_64-linux-gnu", "usr/lib64"),
    ("usr/lib/i386-linux-gnu", "usr/lib"),
    ("lib/i386-linux-gnu", "usr/lib"),
    ("usr/lib32", "usr/lib"),
    ("bin", "usr/bin"),
    ("sbin", "usr/sbin"),
    ("lib64", "usr/lib64"),
    ("lib", "usr/lib"),
)

# Directories owned by Fedora's `filesystem` package (and friends). A
# generated RPM must never claim these as %dir -- that is exactly the
# failure mode that makes `alien` output uninstallable.
UNOWNABLE_DIRS: frozenset[str] = frozenset(
    {
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/usr/libexec",
        "/usr/share",
        "/usr/include",
        "/usr/local",
        "/etc",
        "/opt",
        "/var",
        "/var/lib",
        "/var/log",
        "/usr/share/applications",
        "/usr/share/icons",
        "/usr/share/icons/hicolor",
        "/usr/share/pixmaps",
        "/usr/share/man",
        "/usr/share/doc",
        "/usr/share/metainfo",
        "/usr/share/mime",
        "/usr/share/mime/packages",
        "/usr/share/bash-completion",
        "/usr/share/bash-completion/completions",
        "/usr/share/zsh",
        "/usr/share/licenses",
        "/usr/share/dbus-1",
        "/usr/share/dbus-1/services",
        "/usr/share/glib-2.0",
        "/usr/share/glib-2.0/schemas",
        "/etc/xdg",
        "/etc/xdg/autostart",
        "/etc/profile.d",
        "/etc/cron.d",
        "/etc/cron.daily",
    }
    | {f"/usr/share/man/man{n}" for n in range(1, 10)}
    | {
        f"/usr/share/icons/hicolor/{size}"
        for size in (
            "16x16", "22x22", "24x24", "32x32", "36x36", "48x48", "64x64",
            "72x72", "96x96", "128x128", "192x192", "256x256", "512x512",
            "scalable", "symbolic",
        )
    }
    | {
        f"/usr/share/icons/hicolor/{size}/{kind}"
        for size in (
            "16x16", "22x22", "24x24", "32x32", "48x48", "64x64", "96x96",
            "128x128", "192x192", "256x256", "512x512", "scalable",
        )
        for kind in ("apps", "mimetypes", "status", "actions", "devices")
    }
)

# Debian packaging droppings that must not ship in an RPM.
DROP_PATTERNS: tuple[str, ...] = (
    "usr/share/doc/*/changelog.Debian.gz",
    "usr/share/doc/*/changelog.Debian",
    "usr/share/doc/*/README.Debian",
    "usr/share/doc/*/copyright.debian",
    "usr/share/menu/*",
    "usr/share/lintian/*",
    "DEBIAN/*",
)


@dataclass
class Rewrite:
    src: str
    dst: str

    def __str__(self) -> str:
        return f"/{self.src} -> /{self.dst}"


@dataclass
class Relocation:
    """Result of translating a payload into a Fedora-shaped buildroot."""

    buildroot: Path
    rewrites: list[Rewrite] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    dirs: list[str] = field(default_factory=list)
    symlinks: dict[str, str] = field(default_factory=dict)
    setuid: list[str] = field(default_factory=list)
    private_prefixes: list[str] = field(default_factory=list)
    absolute_links: dict[str, str] = field(default_factory=dict)

    @property
    def ownable_dirs(self) -> list[str]:
        """Directories the RPM may safely own."""
        return [d for d in self.dirs if d not in UNOWNABLE_DIRS]


def translate(rel_path: str) -> str:
    """Map one payload-relative path from Debian layout to Fedora layout."""
    for deb, fed in REWRITES:
        if rel_path == deb:
            return fed
        if rel_path.startswith(deb + "/"):
            return fed + rel_path[len(deb):]
    return rel_path


def _should_drop(rel_path: str) -> bool:
    from fnmatch import fnmatch

    return any(fnmatch(rel_path, pat) for pat in DROP_PATTERNS)


def _assert_inside(root: Path, target: Path) -> None:
    """Refuse to touch a path that resolves outside the buildroot.

    Extraction already rejects escaping links, but relocation walks the
    payload and re-creates it elsewhere, so it must not rely on that.
    Any directory in the target chain could be a symlink; resolving the
    parent catches a write that would follow one out of the tree.
    """
    try:
        resolved = target.parent.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot resolve {target}: {exc}") from exc
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError(
            f"refusing to write outside the buildroot: {target} "
            f"resolves into {resolved}"
        )


def relocate(payload: Path, buildroot: Path) -> Relocation:
    """Copy payload into buildroot, rewriting paths into Fedora layout.

    Never touches anything outside buildroot. Preserves symlinks and modes.
    """
    result = Relocation(buildroot=buildroot)
    buildroot.mkdir(parents=True, exist_ok=True)

    for src in sorted(payload.rglob("*")):
        rel = src.relative_to(payload).as_posix()

        if _should_drop(rel):
            result.dropped.append("/" + rel)
            continue

        new_rel = translate(rel)
        if new_rel != rel:
            result.rewrites.append(Rewrite(rel, new_rel))

        target = buildroot / new_rel

        if src.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            _assert_inside(buildroot, target)
            link = os.readlink(src)
            # An absolute symlink pointing into a rewritten tree needs the
            # same treatment as a real path.
            if link.startswith("/"):
                translated = "/" + translate(link.lstrip("/"))
                if translated != link:
                    link = translated
                result.absolute_links["/" + new_rel] = link
            if target.is_symlink() or target.exists():
                target.unlink()
            # A link that resolves to itself makes rpm fail to stat the
            # file with an error that looks like a toolchain fault rather
            # than a bad package.
            if not link.startswith("/"):
                resolved = os.path.normpath(
                    os.path.join(os.path.dirname("/" + new_rel), link)
                )
                if resolved == "/" + new_rel:
                    raise ValueError(
                        f"symlink points at itself: /{new_rel} -> {link}"
                    )
            os.symlink(link, target)
            result.symlinks["/" + new_rel] = link
            continue

        if src.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            _assert_inside(buildroot, target)
            shutil.copystat(src, target)
            result.dirs.append("/" + new_rel)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        _assert_inside(buildroot, target)
        shutil.copy2(src, target, follow_symlinks=False)
        result.files.append("/" + new_rel)

        mode = src.stat().st_mode
        if mode & (stat.S_ISUID | stat.S_ISGID):
            result.setuid.append("/" + new_rel)

    result.dirs.sort()
    result.files.sort()
    result.private_prefixes = _detect_private_prefixes(result.dirs)
    return result


def _detect_private_prefixes(dirs: list[str]) -> list[str]:
    """Find self-contained install roots, e.g. /opt/vendor/app, /usr/lib/app.

    Files under these get their Provides filtered -- a bundled libffmpeg.so
    must not advertise itself to the rest of the system.
    """
    prefixes: list[str] = []
    for d in dirs:
        parts = d.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "opt":
            prefixes.append(d)
        elif len(parts) == 3 and parts[:2] in (["usr", "lib"], ["usr", "lib64"]):
            prefixes.append(d)
        elif len(parts) == 3 and parts[:2] == ["usr", "share"]:
            continue
    # keep only the shallowest of any nested pair
    out: list[str] = []
    for p in sorted(prefixes):
        if not any(p.startswith(o + "/") for o in out):
            out.append(p)
    return out
