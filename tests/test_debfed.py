"""debfed test suite.

Run with:  python -m pytest tests/ -v

Tests that need rpmbuild or dnf are skipped automatically when those
tools are absent, so the suite is useful on any machine.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from debfed import layout, mapping, spec
from debfed.deb import DebError, parse_control, parse_depends, read_ar, unpack
from debfed.depsolve import Resolution
from debfed.refuse import SAFE_TRIGGERS, Verdict, assess
from debfed.scripts import analyse_scripts

HAS_RPMBUILD = shutil.which("rpmbuild") is not None
HAS_RPMDEPS = any(
    Path(p).is_file() for p in ("/usr/lib/rpm/rpmdeps", "/usr/lib64/rpm/rpmdeps")
)


# ------------------------------------------------------------ deb fixtures


def make_deb(tmp: Path, name: str, version: str, files: dict[str, bytes],
             control_extra: str = "", scripts: dict[str, str] | None = None,
             triggers: str | None = None) -> Path:
    """Build a minimal .deb without dpkg-deb."""
    control_text = (
        f"Package: {name}\n"
        f"Version: {version}\n"
        "Architecture: amd64\n"
        "Maintainer: Test <t@example.invalid>\n"
        f"{control_extra}"
        f"Description: {name} test package\n"
        " Long description line.\n"
    )

    def tar_bytes(entries: dict[str, bytes], modes: dict[str, int] | None = None):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for path, blob in entries.items():
                info = tarfile.TarInfo("./" + path.lstrip("/"))
                info.size = len(blob)
                info.mode = (modes or {}).get(path, 0o644)
                tf.addfile(info, io.BytesIO(blob))
        return buf.getvalue()

    control_entries = {"control": control_text.encode()}
    for sname, body in (scripts or {}).items():
        control_entries[sname] = body.encode()
    if triggers:
        control_entries["triggers"] = triggers.encode()

    members = [
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", tar_bytes(control_entries,
                                     {k: 0o755 for k in (scripts or {})})),
        ("data.tar.gz", tar_bytes(files, {k: 0o755 for k in files
                                          if "/bin/" in k})),
    ]
    out = tmp / f"{name}_{version}_amd64.deb"
    with out.open("wb") as fh:
        fh.write(b"!<arch>\n")
        for member_name, blob in members:
            header = (
                f"{member_name:<16}{'0':<12}{'0':<6}{'0':<6}"
                f"{'100644':<8}{len(blob):<10}"
            ).encode()
            fh.write(header + b"`\n")
            fh.write(blob)
            if len(blob) % 2:
                fh.write(b"\n")
    return out


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    return tmp_path


# ------------------------------------------------------------------ parsing


def test_read_ar_rejects_non_ar(tmp: Path):
    bad = tmp / "bad.deb"
    bad.write_bytes(b"not an archive at all")
    with pytest.raises(DebError):
        read_ar(bad)


def test_parse_control_multiline():
    text = (
        "Package: foo\n"
        "Description: short\n"
        " first\n"
        " second\n"
        "Depends: libc6\n"
    )
    fields = parse_control(text)
    assert fields["Package"] == "foo"
    assert "first" in fields["Description"]
    assert fields["Depends"] == "libc6"


def test_parse_depends_versions_and_alternatives():
    deps = parse_depends("libc6 (>= 2.34), libfoo | libbar, libbaz:amd64")
    assert [d.name for d in deps] == ["libc6", "libfoo", "libbaz"]
    assert deps[0].relation == ">="
    assert deps[0].version == "2.34"
    assert deps[1].alternatives == ("libbar",)


def test_unpack_roundtrip(tmp: Path):
    deb = make_deb(tmp, "demo", "1.2.3-4", {"usr/bin/demo": b"#!/bin/sh\n"})
    work = tmp / "work"
    d = unpack(deb, work)
    assert d.name == "demo"
    assert d.version == "1.2.3-4"
    assert (d.payload_dir / "usr/bin/demo").is_file()


# ------------------------------------------------------------------- layout


@pytest.mark.parametrize(
    "src,expected",
    [
        ("usr/lib/x86_64-linux-gnu/libfoo.so.1", "usr/lib64/libfoo.so.1"),
        ("lib/x86_64-linux-gnu/libbar.so", "usr/lib64/libbar.so"),
        ("bin/tool", "usr/bin/tool"),
        ("sbin/daemon", "usr/sbin/daemon"),
        ("lib/systemd/system/x.service", "usr/lib/systemd/system/x.service"),
        ("usr/share/applications/a.desktop", "usr/share/applications/a.desktop"),
        ("opt/vendor/app", "opt/vendor/app"),
    ],
)
def test_translate_paths(src, expected):
    assert layout.translate(src) == expected


def test_unownable_dirs_cover_the_alien_failure():
    # These are the exact paths that make `alien` output conflict with
    # the `filesystem` package.
    for d in ("/usr/bin", "/usr/lib64", "/usr/share/applications", "/opt"):
        assert d in layout.UNOWNABLE_DIRS


def test_relocate_preserves_symlinks(tmp: Path):
    payload = tmp / "payload"
    (payload / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
    (payload / "usr/lib/x86_64-linux-gnu/libz.so.1.2.3").write_bytes(b"\x7fELF")
    os.symlink("libz.so.1.2.3", payload / "usr/lib/x86_64-linux-gnu/libz.so.1")

    reloc = layout.relocate(payload, tmp / "buildroot")
    assert "/usr/lib64/libz.so.1.2.3" in reloc.files
    assert "/usr/lib64/libz.so.1" in reloc.symlinks
    assert len(reloc.rewrites) >= 2


def test_relocate_drops_debian_droppings(tmp: Path):
    payload = tmp / "payload"
    (payload / "usr/share/doc/app").mkdir(parents=True)
    (payload / "usr/share/doc/app/changelog.Debian.gz").write_bytes(b"x")
    (payload / "usr/share/doc/app/README").write_bytes(b"y")

    reloc = layout.relocate(payload, tmp / "buildroot")
    assert "/usr/share/doc/app/changelog.Debian.gz" in reloc.dropped
    assert "/usr/share/doc/app/README" in reloc.files


def test_private_prefix_detection(tmp: Path):
    payload = tmp / "payload"
    (payload / "opt/vendorapp/lib").mkdir(parents=True)
    (payload / "opt/vendorapp/lib/libbundled.so").write_bytes(b"\x7fELF")
    reloc = layout.relocate(payload, tmp / "buildroot")
    assert "/opt/vendorapp" in reloc.private_prefixes


# ------------------------------------------------------------------ version


@pytest.mark.parametrize(
    "deb_version,expected",
    [
        ("1.7.1-3build1", (None, "1.7.1", "3build1")),
        ("2.1.4-1", (None, "2.1.4", "1")),
        ("1:2.3.4-5ubuntu2", ("1", "2.3.4", "5ubuntu2")),
        ("0.9", (None, "0.9", "1")),
        ("1.0~beta1-1", (None, "1.0~beta1", "1")),
    ],
)
def test_split_version(deb_version, expected):
    assert spec.split_version(deb_version) == expected


def test_split_version_never_emits_dash():
    for v in ("1.2-3-4", "weird--version", "a-b-c-d"):
        _, version, release = spec.split_version(v)
        assert "-" not in version
        assert "-" not in release


# ------------------------------------------------------------------ refusal


def _empty_reloc(tmp: Path) -> layout.Relocation:
    return layout.Relocation(buildroot=tmp)


def test_refuses_base_package(tmp: Path):
    deb = make_deb(tmp, "libc6", "2.39-1", {"usr/lib/x86_64-linux-gnu/libc.so.6": b"x"})
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is Verdict.REFUSE
    assert any(f.code == "BASE_PACKAGE" for f in a.fatal)


def test_refuses_kernel_path(tmp: Path):
    deb = make_deb(tmp, "some-driver", "1.0-1",
                   {"usr/lib/modules/6.1.0/extra/mod.ko": b"x"})
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    a = assess(d, reloc, Resolution())
    assert a.verdict is Verdict.REFUSE
    assert any(f.code == "SYSTEM_PATH" for f in a.fatal)


def test_refuses_pre_depends(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"},
                   control_extra="Pre-Depends: dpkg (>= 1.19)\n")
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is Verdict.REFUSE
    assert any(f.code == "PRE_DEPENDS" for f in a.fatal)


def test_refuses_dpkg_divert(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"},
                   scripts={"postinst": "#!/bin/sh\ndpkg-divert --add /usr/bin/x\n"})
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is Verdict.REFUSE
    assert any(f.code == "DIVERT" for f in a.fatal)


def test_ldconfig_trigger_is_not_a_refusal(tmp: Path):
    """dh_makeshlibs adds this to nearly every library package.

    Refusing on the presence of a triggers file rejects most of Debian
    for no reason. This is a regression test for that bug.
    """
    deb = make_deb(tmp, "libdemo1", "1.0-1",
                   {"usr/lib/x86_64-linux-gnu/libdemo.so.1": b"x"},
                   triggers="# added by dh_makeshlibs\nactivate-noawait ldconfig\n")
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is not Verdict.REFUSE
    assert not any(f.code == "TRIGGERS" for f in a.fatal)


def test_unknown_trigger_is_a_refusal(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"},
                   triggers="interest-noawait /some/weird/path\n")
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is Verdict.REFUSE


def test_glibc_skew_refused(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"})
    d = unpack(deb, tmp / "w")
    res = Resolution(
        requires=["libc.so.6(GLIBC_2.99)(64bit)"],
        unsatisfied=["libc.so.6(GLIBC_2.99)(64bit)"],
    )
    a = assess(d, _empty_reloc(tmp), res)
    assert a.verdict is Verdict.REFUSE
    assert any(f.code == "GLIBC_SKEW" for f in a.fatal)


def test_toolkit_gap_refused(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"})
    d = unpack(deb, tmp / "w")
    res = Resolution(requires=["libgtk-3.so.0()(64bit)"],
                     unsatisfied=["libgtk-3.so.0()(64bit)"])
    a = assess(d, _empty_reloc(tmp), res)
    assert a.verdict is Verdict.REFUSE
    assert any(f.code == "TOOLKIT_GAP" for f in a.fatal)


def test_leaf_gap_falls_to_strategy_b(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"})
    d = unpack(deb, tmp / "w")
    res = Resolution(requires=["libcurious.so.7()(64bit)"],
                     unsatisfied=["libcurious.so.7()(64bit)"])
    a = assess(d, _empty_reloc(tmp), res)
    assert a.verdict is Verdict.STRATEGY_B


def test_unchecked_resolution_never_claims_a_strategy(tmp: Path):
    """--offline must not report a verdict it did not verify."""
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"})
    d = unpack(deb, tmp / "w")
    res = Resolution(requires=["libc.so.6()(64bit)"], checked=False)
    a = assess(d, _empty_reloc(tmp), res)
    assert a.verdict is Verdict.UNKNOWN


# ------------------------------------------------------------------ scripts


def test_apt_registration_is_stripped():
    body = (
        "#!/bin/sh\n"
        "echo 'deb https://apt.vendor.example stable main' "
        "> /etc/apt/sources.list.d/vendor.list\n"
        "curl -s https://vendor.example/key.gpg | gpg --dearmor "
        "> /etc/apt/trusted.gpg.d/vendor.gpg\n"
        "update-desktop-database || true\n"
    )
    plan = analyse_scripts({"postinst": body}, [], SAFE_TRIGGERS)
    assert any("apt repository" in s for s in plan.stripped)
    assert any("apt signing key" in s for s in plan.stripped)
    assert "update-desktop-database &>/dev/null || :" in plan.post


def test_apparmor_is_stripped():
    plan = analyse_scripts(
        {"postinst": "#!/bin/sh\napparmor_parser -r /etc/apparmor.d/app\n"},
        [], SAFE_TRIGGERS,
    )
    assert any("AppArmor" in s for s in plan.stripped)


def test_ldconfig_trigger_becomes_scriptlet():
    plan = analyse_scripts({}, [("activate-noawait", "ldconfig")], SAFE_TRIGGERS)
    assert "/sbin/ldconfig" in plan.post
    assert "/sbin/ldconfig" in plan.postun


# ------------------------------------------------------------------ mapping


def test_builtin_mapping_loads():
    db = mapping.load()
    assert db.lookup("fonts-liberation") == ["liberation-fonts"]
    assert db.lookup("libc6") == []          # implicitly satisfied
    assert db.lookup("no-such-package") is None


def test_mapping_resolve_all():
    db = mapping.load()
    found, unmapped = db.resolve_all(["fonts-liberation", "libc6", "weird-thing"])
    assert "liberation-fonts" in found
    assert unmapped == ["weird-thing"]


def test_libcrypt_compat_is_mapped():
    """Fedora ships libcrypt.so.2; Debian binaries want libcrypt.so.1."""
    assert mapping.load().lookup("libcrypt1") == ["libxcrypt-compat"]


# ------------------------------------------------------------------ spec


def test_spec_never_owns_shared_directories(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {
        "usr/bin/app": b"x",
        "usr/share/applications/app.desktop": b"[Desktop Entry]\n",
    })
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A")
    text = spec.render(plan, reloc.buildroot)

    for forbidden in ("%dir /usr/bin", "%dir /usr/share/applications",
                      "%dir /usr", "%dir /usr/share"):
        assert forbidden not in text, f"spec claims {forbidden}"
    assert "/usr/bin/app" in text


def test_spec_filters_provides_for_private_prefix(tmp: Path):
    deb = make_deb(tmp, "vendorapp", "1.0-1",
                   {"opt/vendorapp/lib/libbundled.so": b"\x7fELF"})
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A")
    text = spec.render(plan, reloc.buildroot)
    assert "__provides_exclude_from" in text
    assert "/opt/vendorapp" in text


def test_spec_disables_binary_post_processing(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"})
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A")
    text = spec.render(plan, reloc.buildroot)
    for macro in ("%global debug_package %{nil}", "%global __brp_strip %{nil}",
                  "%global __brp_mangle_shebangs %{nil}"):
        assert macro in text


# ------------------------------------------------------------- end to end


@pytest.mark.skipif(not (HAS_RPMBUILD and HAS_RPMDEPS),
                    reason="needs rpm-build")
def test_end_to_end_build_produces_valid_rpm(tmp: Path):
    from debfed.build import build_rpm
    from debfed.depsolve import scan_requires

    payload = tmp / "payload"
    (payload / "usr/bin").mkdir(parents=True)
    shutil.copy("/bin/true", payload / "usr/bin/demotool")

    deb_files = {"usr/bin/demotool": (payload / "usr/bin/demotool").read_bytes()}
    deb = make_deb(tmp, "demotool", "3.2.1-2", deb_files)
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")

    requires = scan_requires(reloc.buildroot)
    assert any("libc.so.6" in r for r in requires), requires

    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A")
    text = spec.render(plan, reloc.buildroot)
    result = build_rpm(text, reloc.buildroot, "demotool", tmp / "rpmbuild")

    assert result.rpm_path.is_file()

    listed = subprocess.run(["rpm", "-qpl", str(result.rpm_path)],
                            capture_output=True, text=True).stdout
    assert "/usr/bin/demotool" in listed
    assert "/usr/bin\n" not in listed          # would conflict with filesystem

    reqs = subprocess.run(["rpm", "-qp", "--requires", str(result.rpm_path)],
                          capture_output=True, text=True).stdout
    assert "libc.so.6" in reqs


# =====================================================================
# Security regression tests
#
# Each of these corresponds to a vulnerability found by adversarial
# review of this code. They are regression tests, not hypotheticals:
# every one of them reproduced against an earlier revision.
# =====================================================================


def _build_deb(tmp: Path, control: str, files: dict[str, bytes],
               links: dict[str, str] | None = None) -> Path:
    """Build a .deb with arbitrary (including hostile) contents."""
    def tar_bytes(entries, link_entries=None):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for path, blob in entries.items():
                info = tarfile.TarInfo("./" + path.lstrip("/"))
                info.size = len(blob)
                tf.addfile(info, io.BytesIO(blob))
            for path, target in (link_entries or {}).items():
                info = tarfile.TarInfo("./" + path.lstrip("/"))
                info.type = tarfile.SYMTYPE
                info.linkname = target
                tf.addfile(info)
        return buf.getvalue()

    members = [
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", tar_bytes({"control": control.encode()})),
        ("data.tar.gz", tar_bytes(files, links)),
    ]
    out = tmp / "evil.deb"
    with out.open("wb") as fh:
        fh.write(b"!<arch>\n")
        for name, blob in members:
            fh.write(
                f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{len(blob):<10}"
                .encode() + b"`\n"
            )
            fh.write(blob)
            if len(blob) % 2:
                fh.write(b"\n")
    return out


def _render(tmp: Path, deb_path: Path) -> str:
    from debfed.scripts import analyse_scripts
    d = unpack(deb_path, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A")
    return spec.render(plan, reloc.buildroot)


def test_description_cannot_inject_rpm_macros(tmp: Path):
    """rpm expands %(cmd) via /bin/sh at spec PARSE time.

    An unsanitised Description field was therefore remote code execution
    during `debfed build` -- a command documented as installing nothing.
    """
    deb = _build_deb(
        tmp,
        "Package: evilapp\nVersion: 1.0-1\nArchitecture: amd64\n"
        "Maintainer: A <a@e.invalid>\n"
        "Description: %(id > /tmp/pwned)\n benign second line\n",
        {"usr/bin/evilapp": b"x"},
    )
    text = _render(tmp, deb)
    assert "%%(id" in text                       # escaped, not merely removed
    # No UNESCAPED macro remains: collapsing '%%' must leave no live '%('.
    assert "%(id" not in text.replace("%%", "")


def test_summary_cannot_break_out_with_newlines(tmp: Path):
    """A newline in a single-line tag would let a Summary append sections."""
    deb = _build_deb(
        tmp,
        "Package: app\nVersion: 1.0-1\nArchitecture: amd64\n"
        "Maintainer: A <a@e.invalid>\n"
        "Description: fine\n benign\n",
        {"usr/bin/app": b"x"},
    )
    d = unpack(deb, tmp / "w")
    d.fields["Description"] = "evil\n%install\nid > /tmp/pwned"
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A")
    text = spec.render(plan, reloc.buildroot)
    # exactly one %install section, the one we generate
    assert text.count("\n%install\n") == 1


def test_package_name_traversal_is_refused(tmp: Path):
    """The name reaches the filesystem as the spec path: traversal is a write."""
    from debfed.sanitize import UnsafeInput
    deb = _build_deb(
        tmp,
        "Package: ../../../../tmp/traversed\nVersion: 1.0-1\n"
        "Architecture: amd64\nMaintainer: A <a@e.invalid>\n"
        "Description: b\n b\n",
        {"usr/bin/t": b"x"},
    )
    with pytest.raises(UnsafeInput):
        _render(tmp, deb)


@pytest.mark.parametrize("bad", [
    "../../etc/passwd", "a/b", "a b", "a;id", "-leading", "", "a\nb", "a%b",
])
def test_safe_name_rejects_hostile_names(bad):
    from debfed.sanitize import UnsafeInput, safe_name
    with pytest.raises(UnsafeInput):
        safe_name(bad)


def test_files_entry_with_percent_is_refused():
    from debfed.sanitize import UnsafeInput, spec_path
    with pytest.raises(UnsafeInput):
        spec_path("/usr/share/x/%(id > /tmp/pwned)")


def test_files_entry_with_spaces_is_quoted_not_refused():
    from debfed.sanitize import spec_path
    assert spec_path("/usr/share/a b/c") == '"/usr/share/a b/c"'


def test_hostile_url_is_dropped_not_emitted(tmp: Path):
    deb = _build_deb(
        tmp,
        "Package: licapp\nVersion: 1.0-1\nArchitecture: amd64\n"
        "Maintainer: A <a@e.invalid>\n"
        "Homepage: https://x/%(id > /tmp/pwned)\n"
        "Description: b\n b\n",
        {"usr/bin/licapp": b"x"},
    )
    text = _render(tmp, deb)
    assert "%(id" not in text.replace("%%", "")
    assert "URL:" not in text


def test_absolute_symlink_escape_is_refused(tmp: Path, tmp_path_factory):
    """A symlink to an absolute path, with a member written through it."""
    outside = tmp / "outside"
    outside.mkdir()
    deb = _build_deb(
        tmp,
        "Package: linkapp\nVersion: 1.0-1\nArchitecture: amd64\n"
        "Maintainer: A <a@e.invalid>\nDescription: b\n b\n",
        {"opt/linkapp/escape/OWNED": b"escaped"},
        links={"opt/linkapp/escape": str(outside)},
    )
    with pytest.raises(DebError):
        unpack(deb, tmp / "w")
    assert not (outside / "OWNED").exists()


def test_legitimate_absolute_symlink_is_preserved(tmp: Path):
    """/usr/bin/app -> /opt/app/app is the normal vendor shape.

    Blocking this outright (as tarfile's data filter does) would refuse
    Chrome, VS Code and Claude Desktop. Being too strict is also a bug.
    """
    deb = _build_deb(
        tmp,
        "Package: vendorapp\nVersion: 1.0-1\nArchitecture: amd64\n"
        "Maintainer: A <a@e.invalid>\nDescription: b\n b\n",
        {"opt/vendorapp/vendorapp": b"\x7fELF"},
        links={"usr/bin/vendorapp": "/opt/vendorapp/vendorapp"},
    )
    d = unpack(deb, tmp / "w")
    link = d.payload_dir / "usr/bin/vendorapp"
    assert link.is_symlink()
    assert os.readlink(link) == "/opt/vendorapp/vendorapp"


def test_relative_symlink_escape_is_refused(tmp: Path):
    deb = _build_deb(
        tmp,
        "Package: app\nVersion: 1.0-1\nArchitecture: amd64\n"
        "Maintainer: A <a@e.invalid>\nDescription: b\n b\n",
        {"usr/bin/app": b"x"},
        links={"usr/bin/escape": "../../../../../../etc/shadow"},
    )
    with pytest.raises(DebError):
        unpack(deb, tmp / "w")


def test_truncated_ar_member_is_refused(tmp: Path):
    """A declared size larger than the file must not be silently accepted."""
    bad = tmp / "trunc.deb"
    blob = b"short"
    header = f"{'data.tar.gz':<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{999999:<10}"
    bad.write_bytes(b"!<arch>\n" + header.encode() + b"`\n" + blob)
    with pytest.raises(DebError):
        read_ar(bad)


def test_implausible_member_size_is_refused(tmp: Path):
    bad = tmp / "huge.deb"
    header = (
        f"{'data.tar.gz':<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}"
        f"{99999999999:<10}"
    )
    bad.write_bytes(b"!<arch>\n" + header.encode() + b"`\n")
    with pytest.raises(DebError):
        read_ar(bad)


def test_mapping_database_cannot_inject_requires():
    """The mapping DB is user-editable and may be third-party shipped."""
    from debfed.sanitize import safe_requires
    assert safe_requires("gtk3") == "gtk3"
    assert safe_requires("%(id)") is None
    assert safe_requires("foo\nRequires: bar") is None
    assert safe_requires("a" * 500) is None


def test_setuid_bits_are_recorded_even_though_dropped(tmp: Path):
    """The data filter clears them; the user must still be told."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("./opt/app/chrome-sandbox")
        info.size = 4
        info.mode = 0o4755
        tf.addfile(info, io.BytesIO(b"ELF!"))
    data = buf.getvalue()

    ctrl = io.BytesIO()
    with tarfile.open(fileobj=ctrl, mode="w:gz") as tf:
        body = (b"Package: app\nVersion: 1.0-1\nArchitecture: amd64\n"
                b"Maintainer: A <a@e.invalid>\nDescription: b\n b\n")
        info = tarfile.TarInfo("./control")
        info.size = len(body)
        tf.addfile(info, io.BytesIO(body))
    control = ctrl.getvalue()

    out = tmp / "suid.deb"
    with out.open("wb") as fh:
        fh.write(b"!<arch>\n")
        for name, blob in (("debian-binary", b"2.0\n"),
                           ("control.tar.gz", control),
                           ("data.tar.gz", data)):
            fh.write(
                f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{len(blob):<10}"
                .encode() + b"`\n"
            )
            fh.write(blob)
            if len(blob) % 2:
                fh.write(b"\n")

    d = unpack(out, tmp / "w")
    assert any("chrome-sandbox" in p for p in d.payload_setuid)
    extracted = d.payload_dir / "opt/app/chrome-sandbox"
    assert not extracted.stat().st_mode & 0o4000   # bit actually dropped


def test_attack_suite_refuses_when_a_tool_is_missing(tmp: Path):
    """The attack suite must not report success when it tested nothing.

    A missing marker file only proves an attack failed if debfed actually
    reached a verdict. An earlier revision could not tell the two apart,
    so a missing rpmbuild printed "all 9 attacks blocked" -- a green
    security gate that had run no attacks at all.
    """
    suite = Path(__file__).parent / "attack_suite.py"
    env = dict(os.environ)
    env["PATH"] = "/nonexistent"        # hides rpmbuild
    proc = subprocess.run(
        [sys.executable, str(suite)],
        capture_output=True, text=True, cwd=tmp, env=env, timeout=300,
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 2, (
        f"expected exit 2 (unusable), got {proc.returncode}\n{combined}"
    )
    assert "SUITE UNUSABLE" in combined
    assert "attacks blocked" not in combined


def test_attack_suite_rejects_non_verdict_exit_codes():
    """Exit 2 means debfed could not decide; it is not a clean refusal."""
    import importlib.util
    spec_ = importlib.util.spec_from_file_location(
        "attack_suite", Path(__file__).parent / "attack_suite.py"
    )
    mod = importlib.util.module_from_spec(spec_)
    spec_.loader.exec_module(mod)
    assert mod.VERDICT_CODES == (0, 1), "exit 2 must not count as a verdict"
    assert "not found. Install it" in mod.DID_NOT_RUN


def test_attack_suite_canary_catches_a_broken_toolchain(tmp: Path):
    """A present-but-broken rpmbuild must abort the suite, not pass it.

    Checking that a tool exists is not the same as checking it works.
    The canary converts a known-good package first; if that fails, no
    later "no marker appeared" result means anything.
    """
    fake = tmp / "bin"
    fake.mkdir()
    broken = fake / "rpmbuild"
    broken.write_text("#!/bin/sh\nexit 1\n")
    broken.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{fake}:{env.get('PATH', '')}"
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "attack_suite.py")],
        capture_output=True, text=True, env=env, timeout=300,
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 2, f"expected 2, got {proc.returncode}\n{combined}"
    assert "SUITE UNUSABLE" in combined
    assert "attacks blocked" not in combined


# =====================================================================
# Regressions from converting a real Electron application (VSCodium).
# Each of these reported a dependency as missing when it was not, or
# refused a package that should have converted.
# =====================================================================


def _elf(machine: int, bits64: bool = True) -> bytes:
    """Minimal ELF header with a given e_machine."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2 if bits64 else 1
    header[5] = 1                       # little endian
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header)


def test_foreign_architecture_binaries_are_not_scanned(tmp: Path):
    """Vendor packages bundle ARM and ppc64 helpers.

    Scanning them yields ld-linux-aarch64.so.1 and friends, which no
    x86_64 host can satisfy -- they look like missing dependencies
    instead of files for a different CPU.
    """
    from debfed.elf import partition_by_arch

    (tmp / "x86").write_bytes(_elf(0x3E))
    (tmp / "arm64").write_bytes(_elf(0xB7))
    (tmp / "armhf").write_bytes(_elf(0x28))
    (tmp / "data.json").write_bytes(b"{}")

    ours, foreign = partition_by_arch(
        [tmp / "x86", tmp / "arm64", tmp / "armhf", tmp / "data.json"], "x86_64"
    )
    names = {p.name for p in ours}
    assert names == {"x86", "data.json"}, names
    assert set(foreign) == {"aarch64", "arm"}


def test_old_glibc_symbols_are_not_version_skew():
    """GLIBC_2.2.4 is ancient, not futuristic.

    The x86_64 glibc symbol namespace starts at GLIBC_2.2.5, so lower
    versions are unsatisfiable while being far older than any current
    glibc. They come from other-architecture binaries. Treating any
    unsatisfied libc symbol as skew refuses working packages.
    """
    res = Resolution(
        unsatisfied=[
            "libc.so.6(GLIBC_2.2)(64bit)",
            "libc.so.6(GLIBC_2.2.4)(64bit)",
            "libc.so.6(GLIBC_2.17)(64bit)",
        ]
    )
    assert res.needs_newer_glibc is None


def test_genuinely_newer_glibc_is_still_skew():
    res = Resolution(unsatisfied=["libc.so.6(GLIBC_2.99)(64bit)"])
    assert res.needs_newer_glibc == "libc.so.6(GLIBC_2.99)(64bit)"


def test_usrmerge_file_capabilities_are_normalised():
    """Fedora records file provides under /usr; /bin is a symlink."""
    from debfed.depsolve import normalise_capability

    assert normalise_capability("/bin/bash") == "/usr/bin/bash"
    assert normalise_capability("/sbin/ldconfig") == "/usr/sbin/ldconfig"
    assert normalise_capability("/usr/bin/env") == "/usr/bin/env"
    assert normalise_capability("libc.so.6()(64bit)") == "libc.so.6()(64bit)"


def test_usr_share_app_tree_is_a_private_prefix(tmp: Path):
    """Electron apps install under /usr/share/<app>, not only /opt.

    Missing that means their bundled libraries leak into the system
    dependency namespace.
    """
    payload = tmp / "payload"
    (payload / "usr/share/codium").mkdir(parents=True)
    (payload / "usr/share/codium/libffmpeg.so").write_bytes(b"\x7fELF")
    (payload / "usr/share/applications").mkdir(parents=True)
    (payload / "usr/share/applications/c.desktop").write_bytes(b"[Desktop Entry]\n")

    reloc = layout.relocate(payload, tmp / "br")
    assert "/usr/share/codium" in reloc.private_prefixes
    assert "/usr/share/applications" not in reloc.private_prefixes


def test_shared_usr_share_dirs_are_never_private(tmp: Path):
    payload = tmp / "payload"
    for name in ("icons", "locale", "fonts"):
        d = payload / "usr/share" / name
        d.mkdir(parents=True)
        (d / "libthing.so").write_bytes(b"\x7fELF")
    reloc = layout.relocate(payload, tmp / "br")
    assert reloc.private_prefixes == []
