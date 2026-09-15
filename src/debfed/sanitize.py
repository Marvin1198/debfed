"""Sanitisation of untrusted input.

Everything in a .deb is attacker-controlled: control fields, file paths,
symlink targets, member sizes. Two of those reach an interpreter.

The dangerous one is the generated spec. rpm expands ``%(shell command)``
through /bin/sh and ``%{lua:...}`` through an embedded Lua interpreter at
*parse* time -- before any build step runs, and regardless of whether the
resulting package is ever installed. A Description field containing
``%(id > /tmp/pwned)`` is therefore remote code execution with the
privileges of whoever ran debfed.

Every value derived from a .deb must pass through ``spec_value`` (single
line tags), ``spec_text`` (free text bodies) or ``spec_path`` (%files
entries) before being written into a spec. Nothing else is safe.
"""

from __future__ import annotations

import re
import unicodedata

# rpm package names: letters, digits, and + - . _ ; must start alphanumeric.
VALID_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9+._-]*$")

# Anything that could terminate a tag, start a new section, or be read as a
# macro. C0/C1 controls are stripped outright.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

MAX_TAG_LEN = 300
MAX_TEXT_LEN = 8000
MAX_PATH_LEN = 4096


class UnsafeInput(Exception):
    """Input that cannot be made safe and must be refused outright."""


def escape_macros(text: str) -> str:
    """Neutralise rpm macro expansion by doubling every percent sign.

    rpm treats '%%' as a literal '%', so this defeats %(...), %{...},
    %{lua:...} and bare %name expansion in one step. It must be applied
    to the *whole* string; escaping only recognised macro forms leaves
    room for constructs a future rpm learns to expand.
    """
    return text.replace("%", "%%")


def spec_value(value: str, *, limit: int = MAX_TAG_LEN) -> str:
    """Sanitise a value destined for a single-line spec tag.

    Newlines are the escape hatch that turns a Summary into arbitrary
    spec content, so they are collapsed, not escaped.
    """
    if value is None:
        return ""
    text = _CONTROL.sub("", str(value))
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = re.sub(r"\s+", " ", text).strip()
    text = escape_macros(text)
    return text[:limit]


def spec_text(value: str, *, limit: int = MAX_TEXT_LEN) -> str:
    """Sanitise a multi-line body such as %description.

    Newlines survive, but no line may begin with '%' -- that would open a
    new spec section and let a Description append its own %install.
    """
    if value is None:
        return ""
    text = _CONTROL.sub("", str(value))
    out: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = escape_macros(line.rstrip())
        if line.startswith("%"):
            line = " " + line
        out.append(line[:MAX_TAG_LEN])
    return "\n".join(out)[:limit]


def safe_name(name: str) -> str:
    """Validate a package name, or refuse.

    A name reaches the filesystem (the spec filename) as well as the spec
    body, so path separators and traversal sequences are fatal rather
    than something to strip and continue from.
    """
    if not name:
        raise UnsafeInput("package name is empty")
    name = name.strip()
    if len(name) > 128:
        raise UnsafeInput(f"package name is too long ({len(name)} chars)")
    if not VALID_NAME.match(name):
        raise UnsafeInput(
            f"package name {name!r} contains characters that are not valid "
            "in an rpm name (expected letters, digits, and + - . _)"
        )
    return name


def spec_url(value: str) -> str:
    """Validate a URL for the URL: tag, or return empty.

    rpm requires this tag to be a single token, so a value containing
    whitespace fails the build rather than producing a package. Since a
    homepage is cosmetic, an unusable one is dropped.
    """
    value = _CONTROL.sub("", str(value or "")).strip()
    if not value or len(value) > 200:
        return ""
    if not re.match(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$", value):
        return ""
    if "%" in value:
        return ""
    return value


def spec_path(path: str) -> str:
    """Sanitise a path for a %files entry, or refuse.

    A path cannot be rewritten without changing which file is packaged,
    so anything unsafe is refused instead of altered.
    """
    if not path.startswith("/"):
        raise UnsafeInput(f"payload path is not absolute: {path!r}")
    if len(path) > MAX_PATH_LEN:
        raise UnsafeInput(f"payload path is too long: {len(path)} chars")
    if _CONTROL.search(path) or "\n" in path:
        raise UnsafeInput(f"payload path contains control characters: {path!r}")
    if "\\" in path:
        raise UnsafeInput(f"payload path contains a backslash: {path!r}")
    if "%" in path:
        # Escaping to '%%' stops rpm expanding it, but rpm's %files parser
        # still mishandles the result. A file cannot be renamed without
        # changing what gets packaged, so refuse and say why.
        raise UnsafeInput(
            f"payload path contains '%', which rpm cannot represent in "
            f"%files: {path!r}"
        )

    normalised = unicodedata.normalize("NFC", path)
    quoted = escape_macros(normalised)
    if re.search(r'[\s"\']', quoted):
        quoted = '"' + quoted.replace('"', r"\"") + '"'
    return quoted


def safe_requires(cap: str) -> str | None:
    """Validate a dependency string before it becomes a Requires: line.

    These come from the mapping database, which is user-editable and may
    be shipped by a third party, so it is not trusted either.
    """
    cap = cap.strip()
    if not cap or len(cap) > 200:
        return None
    if _CONTROL.search(cap) or "\n" in cap or "%" in cap:
        return None
    if not re.match(r"^[a-zA-Z0-9][\w+.\-()<>=\s:/]*$", cap):
        return None
    return cap
