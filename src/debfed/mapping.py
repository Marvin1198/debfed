"""The dependency mapping database.

Sonames carry almost all of the real dependency information and rpm
resolves those itself, so this database is deliberately small. It exists
only for requirements that are not ELF-expressible:

  * fonts and icon themes
  * helper binaries an application execs at runtime
  * data packages with no library of their own

If you find yourself wanting to add a soname mapping here, that is a
signal that something upstream is wrong: check `dnf provides` for the
soname first.

YAML is used because it is the only format Fedora ships by default that
humans will actually hand-edit. PyYAML is in the base repos as
python3-pyyaml.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

BUILTIN = Path(__file__).parent / "data" / "mappings.yaml"


def user_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "debfed" / "mappings.yaml"


@dataclass
class MappingDB:
    packages: dict[str, list[str]]
    ignore: set[str]
    version: str = "0"
    sources: list[str] = None  # type: ignore[assignment]

    def lookup(self, deb_name: str) -> list[str] | None:
        """Fedora packages for a Debian package name, or None if unknown."""
        if deb_name in self.ignore:
            return []
        return self.packages.get(deb_name)

    def resolve_all(self, deb_names: list[str]) -> tuple[list[str], list[str]]:
        """Returns (fedora_requires, unmapped_names)."""
        found: list[str] = []
        unmapped: list[str] = []
        for name in deb_names:
            mapped = self.lookup(name)
            if mapped is None:
                unmapped.append(name)
            else:
                found.extend(mapped)
        return sorted(set(found)), unmapped


def _load_file(path: Path) -> dict:
    if not path.is_file():
        return {}
    if yaml is None:
        raise RuntimeError(
            "PyYAML is required to read the mapping database. "
            "Install it:  dnf install python3-pyyaml"
        )
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    return data


def load(extra: Path | None = None) -> MappingDB:
    """Built-in database, overlaid with the user's, overlaid with --map-file."""
    packages: dict[str, list[str]] = {}
    ignore: set[str] = set()
    version = "0"
    sources: list[str] = []

    for path in (BUILTIN, user_path(), extra):
        if path is None:
            continue
        data = _load_file(path)
        if not data:
            continue
        sources.append(str(path))
        version = str(data.get("version", version))
        for deb_name, fedora in (data.get("packages") or {}).items():
            if fedora is None:
                ignore.add(deb_name)
            elif isinstance(fedora, str):
                packages[deb_name] = [fedora]
            else:
                packages[deb_name] = list(fedora)
        ignore.update(data.get("ignore") or [])

    return MappingDB(packages=packages, ignore=ignore, version=version,
                     sources=sources)


def add(deb_name: str, fedora: list[str]) -> Path:
    """Add or replace a mapping in the user's database."""
    if yaml is None:
        raise RuntimeError("PyYAML required:  dnf install python3-pyyaml")
    path = user_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _load_file(path) or {"version": "1", "packages": {}}
    data.setdefault("packages", {})[deb_name] = fedora
    path.write_text(yaml.safe_dump(data, sort_keys=True, default_flow_style=False))
    return path


def remove(deb_name: str) -> bool:
    if yaml is None:
        raise RuntimeError("PyYAML required:  dnf install python3-pyyaml")
    path = user_path()
    data = _load_file(path)
    if not data or deb_name not in (data.get("packages") or {}):
        return False
    del data["packages"][deb_name]
    path.write_text(yaml.safe_dump(data, sort_keys=True, default_flow_style=False))
    return True
