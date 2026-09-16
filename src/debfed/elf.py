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
