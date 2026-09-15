"""Reading .deb files. Stdlib only.

A .deb is an ar archive holding three members:
    debian-binary   format version, always "2.0\\n"
    control.tar.*   metadata + maintainer scripts
    data.tar.*      the payload
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

AR_MAGIC = b"!<arch>\n"

# A .deb is an attacker-controlled archive. These caps bound the damage a
# decompression bomb can do: a few hundred KB of compressed input can
# otherwise expand to tens of gigabytes and exhaust memory.
MAX_MEMBER_BYTES = 4 * 1024 * 1024 * 1024      # 4 GiB per ar member
MAX_UNPACKED_BYTES = 8 * 1024 * 1024 * 1024    # 8 GiB total payload
MAX_MEMBERS = 64                               # ar members in one .deb
MAX_ENTRIES = 200_000                          # tar entries in one payload

SCRIPT_NAMES = ("preinst", "postinst", "prerm", "postrm", "config")


class DebError(Exception):
    """Malformed or unreadable .deb."""


# --------------------------------------------------------------------- ar


def read_ar(path: Path) -> dict[str, bytes]:
    """Read an ar archive into {member_name: bytes}."""
    members: dict[str, bytes] = {}
    with path.open("rb") as fh:
        if fh.read(8) != AR_MAGIC:
            raise DebError(f"{path.name}: not an ar archive")
        while True:
            header = fh.read(60)
            if len(header) < 60:
                break
            if header[58:60] != b"`\n":
                raise DebError(f"{path.name}: corrupt ar member header")
            name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
            try:
                size = int(header[48:58].decode("ascii", "replace").strip())
            except ValueError as exc:
                raise DebError(f"{path.name}: bad member size") from exc
            if size < 0 or size > MAX_MEMBER_BYTES:
                raise DebError(
                    f"{path.name}: member {name!r} declares an implausible "
                    f"size ({size} bytes); refusing"
                )
            if len(members) >= MAX_MEMBERS:
                raise DebError(f"{path.name}: too many ar members; refusing")
            blob = fh.read(size)
            if len(blob) != size:
                raise DebError(
                    f"{path.name}: member {name!r} is truncated "
                    f"({len(blob)} of {size} bytes)"
                )
            members[name] = blob
            if size % 2:
                fh.read(1)  # members are 2-byte aligned
    return members


# -------------------------------------------------------------------- tar


def extract_tar(blob: bytes, dest: Path) -> tuple[list[str], list[str]]:
    """Extract a control.tar.* / data.tar.* blob into dest.

    tarfile learned zstd in Python 3.14 (PEP 784). Below that we shell
    out to the zstd binary, which Fedora ships in the base system.
    """
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
            return _safe_extract(tf, dest)
    except tarfile.ReadError:
        pass

    zstd_bin = shutil.which("zstd")
    if zstd_bin is None:
        raise DebError(
            "payload appears zstd-compressed; needs Python >= 3.14 or the "
            "zstd binary"
        )
    try:
        plain = subprocess.run(
            [zstd_bin, "-d", "-c", "--memory=2048MB"],
            input=blob, capture_output=True, check=True,
            timeout=300,
        ).stdout
        if len(plain) > MAX_UNPACKED_BYTES:
            raise DebError("zstd payload expands implausibly; refusing")
    except subprocess.TimeoutExpired as exc:
        raise DebError("zstd decompression timed out; refusing") from exc
    except subprocess.CalledProcessError as exc:
        raise DebError(f"zstd decompression failed: {exc.stderr[:200]!r}") from exc
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as tf:
        return _safe_extract(tf, dest)


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> tuple[list[str], list[str]]:
    """Extract an untrusted tar payload.

    Returns (setuid_paths, absolute_links).

    Absolute symlinks are legitimate and common in vendor packages --
    ``/usr/bin/code -> /opt/code/bin/code`` is the normal shape -- but
    tarfile's ``data`` filter refuses them outright, and the weaker
    ``tar`` filter only catches an escape once some later member writes
    *through* the link.

    So symlinks are deferred: everything else is extracted under the
    strict ``data`` filter, and links are created afterwards, in a second
    pass, once no further member can be written through them. Only the
    link's own location is checked against the destination; its target is
    not followed, because it is resolved on the installed system rather
    than here.

    The data filter also clears setuid/setgid, so those are recorded from
    the header first.
    """
    root = dest.resolve()
    setuid: list[str] = []
    absolute_links: list[str] = []
    deferred: list[tuple[str, str]] = []
    total = 0
    count = 0

    for member in tf.getmembers():
        count += 1
        if count > MAX_ENTRIES:
            raise DebError(f"payload has more than {MAX_ENTRIES} entries; refusing")
        total += max(member.size, 0)
        if total > MAX_UNPACKED_BYTES:
            raise DebError(
                "payload expands beyond "
                f"{MAX_UNPACKED_BYTES // (1024**3)} GiB; refusing "
                "(possible decompression bomb)"
            )
        if member.mode & (0o4000 | 0o2000):
            setuid.append("/" + member.name.lstrip("./"))
        if member.issym():
            deferred.append((member.name, member.linkname))
            if os.path.isabs(member.linkname):
                absolute_links.append(f"{member.name} -> {member.linkname}")

    deferred_names = {name for name, _ in deferred}

    def _filter(member: tarfile.TarInfo, path: str):
        if member.name in deferred_names and member.issym():
            return None  # handled in the second pass
        return tarfile.data_filter(member, path)

    try:
        # nosec B202 - members are validated by _filter, which delegates to
        # tarfile.data_filter for everything it does not defer.
        tf.extractall(dest, filter=_filter)  # nosec B202
    except tarfile.OutsideDestinationError as exc:
        raise DebError(f"payload tries to write outside its own tree: {exc}") from exc
    except tarfile.SpecialFileError as exc:
        raise DebError(f"payload contains a device or fifo: {exc}") from exc
    except tarfile.AbsoluteLinkError as exc:
        raise DebError(f"payload contains an unsafe hard link: {exc}") from exc
    except tarfile.FilterError as exc:
        raise DebError(f"payload rejected by the tar safety filter: {exc}") from exc

    for name, target in deferred:
        rel = os.path.normpath(name.lstrip("./"))
        if rel.startswith("..") or os.path.isabs(rel):
            raise DebError(f"symlink escapes the payload tree: {name}")
        link_path = dest / rel
        parent = link_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        if parent.resolve() != root and root not in parent.resolve().parents:
            raise DebError(f"symlink would be created outside the payload: {name}")
        if not os.path.isabs(target):
            resolved = os.path.normpath(os.path.join(str(parent), target))
            if not (resolved == str(root) or resolved.startswith(str(root) + os.sep)):
                raise DebError(
                    f"relative symlink escapes the payload: {name} -> {target}"
                )
        if link_path.is_dir() and not link_path.is_symlink():
            # The archive declares this path as both a symlink and a real
            # directory. Extraction put the directory down first, so
            # nothing escaped -- but the payload is malformed, and the
            # shape is exactly what a symlink-swap attack looks like.
            raise DebError(
                f"payload declares both a directory and a symlink at {name!r}; "
                "refusing"
            )
        if link_path.is_symlink() or link_path.exists():
            link_path.unlink()
        os.symlink(target, link_path)

    return setuid, absolute_links


# ---------------------------------------------------------------- control


def parse_control(text: str) -> dict[str, str]:
    """Parse the first stanza of a Debian control file."""
    fields: dict[str, str] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if fields:
                break
            continue
        if line[0] in " \t" and key:
            fields[key] += "\n" + line.strip()
        elif ":" in line:
            raw, _, val = line.partition(":")
            key = raw.strip()
            fields[key] = val.strip()
    return fields


@dataclass(frozen=True)
class Dependency:
    name: str
    relation: str | None = None
    version: str | None = None
    alternatives: tuple[str, ...] = ()

    def __str__(self) -> str:
        base = self.name
        if self.relation and self.version:
            base += f" ({self.relation} {self.version})"
        if self.alternatives:
            base += " | " + " | ".join(self.alternatives)
        return base


_DEP_RE = re.compile(
    r"^(?P<name>[a-zA-Z0-9][a-zA-Z0-9+.-]*)"
    r"(?::(?P<arch>[a-z0-9-]+))?"
    r"(?:\s*\(\s*(?P<rel>[<>=]+)\s*(?P<ver>[^)]+)\s*\))?"
)


def parse_depends(value: str) -> list[Dependency]:
    """Parse a Depends/Recommends field into structured dependencies."""
    deps: list[Dependency] = []
    for clause in value.replace("\n", " ").split(","):
        clause = clause.strip()
        if not clause:
            continue
        parts = [p.strip() for p in clause.split("|")]
        primary = _DEP_RE.match(parts[0])
        if not primary:
            continue
        alts = []
        for alt in parts[1:]:
            m = _DEP_RE.match(alt)
            if m:
                alts.append(m.group("name"))
        deps.append(
            Dependency(
                name=primary.group("name"),
                relation=primary.group("rel"),
                version=primary.group("ver"),
                alternatives=tuple(alts),
            )
        )
    return deps


# ------------------------------------------------------------------ facade


@dataclass
class Deb:
    """An unpacked .deb, ready for inspection."""

    path: Path
    control_dir: Path
    payload_dir: Path
    fields: dict[str, str] = field(default_factory=dict)
    payload_setuid: list[str] = field(default_factory=list)
    absolute_links: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.fields.get("Package", self.path.stem)

    @property
    def version(self) -> str:
        return self.fields.get("Version", "0")

    @property
    def architecture(self) -> str:
        return self.fields.get("Architecture", "all")

    @property
    def summary(self) -> str:
        return self.fields.get("Description", "").splitlines()[0] if self.fields.get(
            "Description"
        ) else self.name

    @property
    def description(self) -> str:
        body = self.fields.get("Description", "").splitlines()[1:]
        cleaned = [ln if ln.strip() != "." else "" for ln in body]
        return "\n".join(cleaned).strip() or self.summary

    @property
    def homepage(self) -> str:
        return self.fields.get("Homepage", "")

    @property
    def depends(self) -> list[Dependency]:
        return parse_depends(self.fields.get("Depends", ""))

    @property
    def maintainer_scripts(self) -> dict[str, str]:
        out = {}
        for name in SCRIPT_NAMES:
            p = self.control_dir / name
            if p.is_file():
                out[name] = p.read_text(errors="replace")
        return out

    @property
    def has_triggers(self) -> bool:
        return (self.control_dir / "triggers").is_file()

    @property
    def triggers(self) -> list[tuple[str, str]]:
        """Parsed triggers file as [(directive, target), ...].

        Most library packages carry only `activate-noawait ldconfig`,
        added automatically by dh_makeshlibs. That one maps cleanly onto
        an rpm scriptlet and must not be treated as a blocker.
        """
        p = self.control_dir / "triggers"
        if not p.is_file():
            return []
        out: list[tuple[str, str]] = []
        for line in p.read_text(errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            directive, _, target = line.partition(" ")
            out.append((directive.strip(), target.strip()))
        return out

    @property
    def conffiles(self) -> list[str]:
        p = self.control_dir / "conffiles"
        if not p.is_file():
            return []
        return [
            ln.strip()
            for ln in p.read_text(errors="replace").splitlines()
            if ln.strip()
        ]


def unpack(deb_path: Path, workdir: Path) -> Deb:
    """Unpack a .deb into workdir/{control,payload}. Read-only wrt the system."""
    if not deb_path.is_file():
        raise DebError(f"{deb_path}: no such file")

    members = read_ar(deb_path)

    version_blob = members.get("debian-binary", b"")
    if not version_blob.startswith(b"2."):
        raise DebError(
            f"{deb_path.name}: unsupported deb format version "
            f"{version_blob.decode(errors='replace').strip()!r}"
        )

    control_member = next((k for k in members if k.startswith("control.tar")), None)
    data_member = next((k for k in members if k.startswith("data.tar")), None)
    if not control_member or not data_member:
        raise DebError(f"{deb_path.name}: missing control.tar or data.tar member")

    control_dir = workdir / "control"
    payload_dir = workdir / "payload"
    extract_tar(members[control_member], control_dir)
    setuid, absolute_links = extract_tar(members[data_member], payload_dir)

    control_file = control_dir / "control"
    if not control_file.is_file():
        raise DebError(f"{deb_path.name}: control.tar has no control file")

    return Deb(
        path=deb_path,
        control_dir=control_dir,
        payload_dir=payload_dir,
        fields=parse_control(control_file.read_text(errors="replace")),
        payload_setuid=setuid,
        absolute_links=absolute_links,
    )
