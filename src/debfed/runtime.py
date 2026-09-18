"""Host runtime capabilities.

A .deb declares package-level dependencies. It does not declare what it
assumes about the running system: that unprivileged user namespaces
work, that a session bus exists, that a display server is reachable.
Those assumptions are invisible to dependency resolution and are where
a correctly-converted package still fails to start.

This module probes them so debfed can report a package as convertible
*and* say whether this host will actually run it.

Nothing here modifies the system. Every probe is a read.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


def _read_int(path: str) -> int | None:
    try:
        return int(Path(path).read_text().strip())
    except (OSError, ValueError):
        return None


@dataclass(frozen=True)
class UserNamespaces:
    """Whether an unprivileged process may create a user namespace.

    Chromium and every Electron application use one of two sandbox
    mechanisms: a setuid chrome-sandbox helper, or unprivileged user
    namespaces. With neither, the runtime aborts before opening a window.

    The sysctl to consult differs by distribution. kernel.unprivileged_-
    userns_clone is a Debian/Ubuntu/Arch patch and does not exist
    upstream; Fedora and other upstream-kernel distributions expose
    user.max_user_namespaces instead. Ubuntu 23.10+ adds a third gate,
    restricting namespaces through AppArmor even when the kernel allows
    them.
    """

    available: bool
    mechanism: str
    detail: str

    @property
    def summary(self) -> str:
        return f"{'available' if self.available else 'BLOCKED'} ({self.detail})"


def user_namespaces() -> UserNamespaces:
    # Debian / Ubuntu / Arch patch
    clone = _read_int("/proc/sys/kernel/unprivileged_userns_clone")
    if clone is not None and clone == 0:
        return UserNamespaces(
            False, "unprivileged_userns_clone",
            "kernel.unprivileged_userns_clone=0",
        )

    # Ubuntu 23.10+ restricts via AppArmor even when the kernel permits it
    apparmor = _read_int("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if apparmor == 1:
        return UserNamespaces(
            False, "apparmor",
            "apparmor_restrict_unprivileged_userns=1",
        )

    # Upstream kernel knob, used by Fedora
    maxns = _read_int("/proc/sys/user/max_user_namespaces")
    if maxns is not None:
        if maxns > 0:
            return UserNamespaces(
                True, "max_user_namespaces",
                f"user.max_user_namespaces={maxns}",
            )
        return UserNamespaces(
            False, "max_user_namespaces", "user.max_user_namespaces=0"
        )

    if clone == 1:
        return UserNamespaces(
            True, "unprivileged_userns_clone",
            "kernel.unprivileged_userns_clone=1",
        )

    return UserNamespaces(False, "unknown", "no userns sysctl found")


@dataclass
class HostRuntime:
    """What this host offers an installed desktop application."""

    userns: UserNamespaces
    session_bus: bool
    display: str            # "wayland" | "x11" | "none"
    selinux: str            # "enforcing" | "permissive" | "disabled" | "absent"
    portals: bool

    def as_dict(self) -> dict:
        return {
            "user_namespaces": self.userns.available,
            "user_namespaces_detail": self.userns.detail,
            "session_bus": self.session_bus,
            "display": self.display,
            "selinux": self.selinux,
            "xdg_portals": self.portals,
        }


def _display() -> str:
    if os.environ.get("WAYLAND_DISPLAY"):
        return "wayland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return "none"


def _selinux() -> str:
    mode = Path("/sys/fs/selinux/enforce")
    if not mode.exists():
        return "absent"
    value = _read_int(str(mode))
    if value is None:
        return "absent"
    return "enforcing" if value == 1 else "permissive"


def probe() -> HostRuntime:
    """Read-only inspection of the host's runtime contract."""
    bus = bool(os.environ.get("DBUS_SESSION_BUS_ADDRESS"))
    if not bus:
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
        bus = bool(runtime_dir and Path(runtime_dir, "bus").exists())
    return HostRuntime(
        userns=user_namespaces(),
        session_bus=bus,
        display=_display(),
        selinux=_selinux(),
        portals=shutil.which("xdg-desktop-portal") is not None
        or Path("/usr/libexec/xdg-desktop-portal").exists(),
    )


def sandbox_outlook(has_setuid_helper: bool,
                    setuid_preserved: bool) -> tuple[str, str]:
    """Will a Chromium/Electron application start on this host?

    Returns (severity, explanation) where severity is "ok", "warn" or
    "fatal". A dropped setuid bit is not by itself a failure: with user
    namespaces available the helper runs fine at 0755. It only matters
    when namespaces are unavailable, and then it is the only sandbox
    the application has.
    """
    if not has_setuid_helper:
        return "ok", "package ships no setuid sandbox helper"

    ns = user_namespaces()
    if ns.available:
        return ("ok",
                f"user namespaces are {ns.summary}; Chromium will use the "
                "namespace sandbox and does not need the setuid helper")
    if setuid_preserved:
        return ("warn",
                f"user namespaces are {ns.summary}; the setuid helper is "
                "this application's only sandbox and has been preserved")
    return ("fatal",
            f"user namespaces are {ns.summary} and the setuid bit was "
            "dropped. Chromium will abort before opening a window. Either "
            "enable user namespaces on this host, or rebuild with "
            "--restore-sandbox-setuid, or run the application with "
            "--no-sandbox (which removes a security boundary).")
