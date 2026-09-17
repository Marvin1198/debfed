"""Minimal ELF header inspection.

A vendor package routinely ships helper binaries for architectures other
than the one being converted -- Electron apps bundle ARM and ppc64
variants of node, ripgrep, or a CLI shim. Feeding those to rpm's
dependency generator produces requirements no x86_64 host can satisfy
(``ld-linux-aarch64.so.1``, ``ld-linux-armhf.so.3``), which then look
like missing dependencies rather than what they are: files for a
different machine.

Reading two bytes of the ELF header is enough to tell them apart, and it
needs nothing outside the standard library.
"""

from __future__ import annotations

import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

# e_machine values we care about. The full list is long; anything absent
# is simply "not our architecture", which is the only distinction needed.
EM_386 = 0x03
EM_ARM = 0x28
EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7
EM_PPC64 = 0x15
EM_S390 = 0x16
EM_RISCV = 0xF3

MACHINE_NAMES = {
    EM_386: "i386",
    EM_ARM: "arm",
    EM_X86_64: "x86_64",
    EM_AARCH64: "aarch64",
    EM_PPC64: "ppc64",
    EM_S390: "s390x",
    EM_RISCV: "riscv",
}

# rpm architecture -> the e_machine values that belong to it
ARCH_MACHINES: dict[str, set[int]] = {
    "x86_64": {EM_X86_64},
    "i686": {EM_386},
    "aarch64": {EM_AARCH64},
}


def read_machine(path: Path) -> int | None:
    """Return the ELF e_machine value, or None if this is not an ELF file."""
    try:
        with path.open("rb") as fh:
            header = fh.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != ELF_MAGIC:
        return None
    # EI_DATA at offset 5: 1 = little endian, 2 = big endian
    endian = "<" if header[5] == 1 else ">"
    try:
        return struct.unpack(endian + "H", header[18:20])[0]
    except struct.error:
        return None


def machine_name(machine: int | None) -> str:
    if machine is None:
        return "not-elf"
    return MACHINE_NAMES.get(machine, f"unknown(0x{machine:x})")


def is_elf(path: Path) -> bool:
    return read_machine(path) is not None


def matches_arch(path: Path, arch: str = "x86_64") -> bool:
    """True if the file is an ELF object for the given rpm architecture.

    Non-ELF files return True: they carry no ELF dependencies, so the
    dependency generator's other extractors (shebangs, pkgconfig) should
    still see them.
    """
    machine = read_machine(path)
    if machine is None:
        return True
    return machine in ARCH_MACHINES.get(arch, {EM_X86_64})


def partition_by_arch(
    paths: list[Path], arch: str = "x86_64"
) -> tuple[list[Path], dict[str, list[Path]]]:
    """Split paths into (ours, {machine_name: theirs}).

    The second element exists so the foreign binaries can be reported
    rather than silently ignored -- a package that is mostly the wrong
    architecture is worth telling the user about.
    """
    ours: list[Path] = []
    foreign: dict[str, list[Path]] = {}
    wanted = ARCH_MACHINES.get(arch, {EM_X86_64})
    for path in paths:
        machine = read_machine(path)
        if machine is None or machine in wanted:
            ours.append(path)
        else:
            foreign.setdefault(machine_name(machine), []).append(path)
    return ours, foreign


# ---------------------------------------------------------------- versions

SHT_GNU_VERDEF = 0x6FFFFFFD


def _section_headers(fh, header: bytes):
    """Yield (sh_type, sh_offset, sh_size, sh_link, name_off) for ELF64."""
    if header[4] != 2:                      # EI_CLASS: 64-bit only
        return
    endian = "<" if header[5] == 1 else ">"
    e_shoff = struct.unpack(endian + "Q", header[0x28:0x30])[0]
    e_shentsize = struct.unpack(endian + "H", header[0x3A:0x3C])[0]
    e_shnum = struct.unpack(endian + "H", header[0x3C:0x3E])[0]
    if not e_shoff or not e_shnum or e_shentsize < 64:
        return
    fh.seek(e_shoff)
    raw = fh.read(e_shentsize * e_shnum)
    for i in range(e_shnum):
        ent = raw[i * e_shentsize : i * e_shentsize + 64]
        if len(ent) < 64:
            break
        name_off, sh_type = struct.unpack(endian + "II", ent[0:8])
        sh_offset, sh_size = struct.unpack(endian + "QQ", ent[0x18:0x28])
        sh_link = struct.unpack(endian + "I", ent[0x28:0x2C])[0]
        yield sh_type, sh_offset, sh_size, sh_link, name_off


def has_version_definitions(path: Path) -> bool | None:
    """Does this library define symbol versions at all?

    This decides whether a missing symbol version is fatal. glibc's
    dl-version.c returns success with only a "no version information
    available" warning when the provider has no DT_VERDEF at all -- the
    dependent object was simply linked against a differently-versioned
    build. If the provider DOES define versions but not the required
    one, the load fails.

    So a Debian binary asking for CURL_OPENSSL_4 from Fedora's
    unversioned libcurl runs; asking for a missing GLIBC_ version from
    glibc, which is heavily versioned, does not.

    Returns None if the file cannot be read as ELF.
    """
    try:
        with path.open("rb") as fh:
            header = fh.read(64)
            if len(header) < 64 or header[:4] != ELF_MAGIC:
                return None
            for sh_type, *_ in _section_headers(fh, header):
                if sh_type == SHT_GNU_VERDEF:
                    return True
        return False
    except OSError:
        return None


DEFAULT_LIBRARY_PATHS = (
    "/usr/lib64", "/lib64", "/usr/lib", "/lib",
    "/usr/lib/x86_64-linux-gnu",
)


def find_system_library(soname: str,
                        search: tuple[str, ...] = DEFAULT_LIBRARY_PATHS) -> Path | None:
    """Locate a library the host provides, by soname."""
    for directory in search:
        candidate = Path(directory) / soname
        if candidate.exists():
            return candidate.resolve()
    return None
