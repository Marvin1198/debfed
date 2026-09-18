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


def test_pre_depends_is_informational_not_a_refusal(tmp: Path):
    """Pre-Depends states unpack ordering, not a conflict.

    "Pre-Depends: dpkg" is universally true on Debian and meaningless on
    Fedora. Refusing on its presence rejected Chromium. Being a base
    package is caught separately by BASE_PACKAGES.
    """
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"},
                   control_extra="Pre-Depends: dpkg (>= 1.19), libc6\n")
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is not Verdict.REFUSE
    assert any(f.code == "PRE_DEPENDS" for f in a.warnings)


def test_systemd_unit_path_is_not_a_base_path(tmp: Path):
    """/usr/lib/systemd/system is %{_unitdir} -- where rpms MUST ship units.

    Treating it as a boot path refused every package shipping a service
    file, which is correct behaviour for a daemon.
    """
    deb = make_deb(tmp, "daemonapp", "1.0-1", {
        "usr/bin/daemonapp": b"\x7fELF",
        "usr/lib/systemd/system/daemonapp.service": b"[Unit]\n",
    })
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    a = assess(d, reloc, Resolution())
    assert a.verdict is not Verdict.REFUSE
    assert not any(f.code == "SYSTEM_PATH" for f in a.fatal)


def test_shipped_units_get_lifecycle_scriptlets_but_are_not_enabled(tmp: Path):
    """systemd must be told a unit exists; Fedora presets decide enabling."""
    deb = make_deb(tmp, "daemonapp", "1.0-1", {
        "usr/bin/daemonapp": b"\x7fELF",
        "usr/lib/systemd/system/daemonapp.service": b"[Unit]\n",
    })
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A")
    text = spec.render(plan, reloc.buildroot)
    assert "systemctl daemon-reload" in text
    assert "disable --now daemonapp.service" in text
    assert "systemctl enable" not in text


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


def test_unknown_trigger_warns_but_does_not_refuse(tmp: Path):
    """An unrecognised trigger costs a refresh action, not safety.

    debfed never runs maintainer scripts, so a trigger it cannot map just
    means one refresh does not happen. Refusing on it rejected ordinary
    packages -- ca-certificates and cups among them.
    """
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"},
                   triggers="interest-noawait /some/weird/path\n")
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is not Verdict.REFUSE
    assert any(f.code == "TRIGGERS" for f in a.warnings)


def test_unknown_trigger_refuses_under_strict_scripts(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"x"},
                   triggers="interest-noawait /some/weird/path\n")
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution(), strict_scripts=True)
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


def test_capability_variants_cover_both_usrmerge_spellings():
    """Neither spelling is universally right.

    /bin/bash resolves only as /usr/bin/bash (rpm records the real path),
    but /bin/sh resolves only as /bin/sh (it is a symlink to bash, and rpm
    does not record symlinked paths as file provides -- Fedora carries an
    explicit Provides: /bin/sh instead). Rewriting unconditionally fixes
    the first and breaks the second.
    """
    from debfed.depsolve import capability_variants

    assert capability_variants("/bin/sh") == ["/bin/sh", "/usr/bin/sh"]
    assert capability_variants("/bin/bash") == ["/bin/bash", "/usr/bin/bash"]
    assert capability_variants("/usr/bin/env") == ["/usr/bin/env", "/bin/env"]
    # non-path capabilities are left alone
    assert capability_variants("libc.so.6()(64bit)") == ["libc.so.6()(64bit)"]


def test_repoquery_format_string_terminates_lines():
    """dnf repoquery --qf '%{name}' with no newline concatenates providers.

    Two packages providing one capability then became a single nonexistent
    name such as "libcurllibcurl-minimal", which was recorded as the
    resolving package.
    """
    import inspect as _inspect

    from debfed import depsolve

    source = _inspect.getsource(depsolve._repoquery_one)
    assert '"%{name}\\n"' in source, "repoquery format string must end with a newline"


def test_multiple_providers_are_parsed_separately():
    from unittest import mock

    from debfed.depsolve import _repoquery_one

    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="libcurl\nlibcurl-minimal\n", stderr=""
    )
    with mock.patch("debfed.depsolve.subprocess.run", return_value=fake), \
         mock.patch("debfed.depsolve._dnf_bin", return_value="dnf"):
        assert _repoquery_one("libcurl.so.4()(64bit)") == [
            "libcurl", "libcurl-minimal",
        ]


# =====================================================================
# debconf handling.
#
# Refusing every package that touches debconf rejects a large class of
# working vendor packages. VS Code is the canonical case: every db_* call
# it makes governs one question -- whether to register the Microsoft apt
# repository -- which debfed strips anyway, and upstream ships an explicit
# code path for systems with no debconf at all.
# =====================================================================

VSCODE_POSTINST = """#!/bin/bash
rm -f /usr/bin/codium
update-alternatives --install /usr/bin/editor editor /usr/bin/codium 0
if hash update-desktop-database 2>/dev/null; then update-desktop-database; fi
RET='true'
if [ -e '/usr/share/debconf/confmodule' ]; then
  . /usr/share/debconf/confmodule
  db_get codium/add-microsoft-repo || true
fi
db_input high codium/add-microsoft-repo || true
db_go || true
"""

READ_ONLY_POSTINST = """#!/bin/sh
. /usr/share/debconf/confmodule
db_get myapp/setting || true
db_purge
"""


def test_sourcing_confmodule_alone_is_not_a_refusal(tmp: Path):
    """Sourcing the library displays nothing; it is inert on its own."""
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"\x7fELF"},
                   scripts={"postinst": ". /usr/share/debconf/confmodule\n"})
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is not Verdict.REFUSE


def test_reading_debconf_without_prompting_is_not_a_refusal(tmp: Path):
    """db_get and db_purge read or clear state; neither displays anything."""
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"\x7fELF"},
                   scripts={"postinst": READ_ONLY_POSTINST})
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is not Verdict.REFUSE
    assert any(f.code == "DEBCONF_READ" for f in a.warnings)
    assert not any(f.code.startswith("DEBCONF") for f in a.fatal)


def test_debconf_prompt_warns_but_converts(tmp: Path):
    """db_input falls back to the stored default under a noninteractive
    frontend, which is exactly the outcome of not running the script."""
    deb = make_deb(tmp, "codium", "1.0-1", {"usr/bin/codium": b"\x7fELF"},
                   scripts={"postinst": VSCODE_POSTINST})
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution())
    assert a.verdict is not Verdict.REFUSE
    prompt = [f for f in a.warnings if f.code == "DEBCONF_PROMPT"]
    assert prompt, [f.code for f in a.findings]
    # the question must be named, so the user can judge whether it matters
    assert "codium/add-microsoft-repo" in prompt[0].detail


def test_strict_scripts_restores_the_refusal(tmp: Path):
    deb = make_deb(tmp, "codium", "1.0-1", {"usr/bin/codium": b"\x7fELF"},
                   scripts={"postinst": VSCODE_POSTINST})
    d = unpack(deb, tmp / "w")
    a = assess(d, _empty_reloc(tmp), Resolution(), strict_scripts=True)
    assert a.verdict is Verdict.REFUSE
    assert any(f.code == "DEBCONF_PROMPT" for f in a.fatal)


def test_shared_options_work_after_the_subcommand():
    """`debfed inspect --map-file X` must not be an argparse error."""
    from debfed.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(
        ["inspect", "--offline", "--strict-scripts", "--map-file", "/dev/null", "x.deb"]
    )
    assert args.strict_scripts is True
    assert str(args.map_file) == "/dev/null"

    before = parser.parse_args(["--strict-scripts", "inspect", "x.deb"])
    assert before.strict_scripts is True


def test_directory_ownership_is_an_allowlist(tmp: Path):
    """Enumerating shared directories is unwinnable.

    A 56-package corpus claimed 155 shared directories -- /usr/share/locale
    alone has hundreds. A package may own only directories inside its own
    tree; everything else is left unowned, which rpm handles fine.
    """
    payload = tmp / "payload"
    for d in ("usr/share/locale/fr/LC_MESSAGES", "usr/lib/tmpfiles.d",
              "usr/lib/systemd/system", "etc/default", "usr/games"):
        (payload / d).mkdir(parents=True, exist_ok=True)
        (payload / d / "f").write_bytes(b"x")
    (payload / "usr/lib/myapp").mkdir(parents=True)
    # A real ELF header: the detector reads e_machine at offset 18, so a
    # four-byte stub is correctly not recognised as an object file.
    (payload / "usr/lib/myapp/libmine.so").write_bytes(_elf(0x3E))

    reloc = layout.relocate(payload, tmp / "br")
    owned = reloc.ownable_dirs
    for shared in ("/usr/share/locale", "/usr/share/locale/fr",
                   "/usr/lib/tmpfiles.d", "/usr/lib/systemd",
                   "/usr/lib/systemd/system", "/etc/default", "/usr/games"):
        assert shared not in owned, f"claims shared directory {shared}"
    assert "/usr/lib/myapp" in owned


def test_distribution_dropin_dirs_are_not_private_prefixes(tmp: Path):
    """/usr/lib/udev holds config, not one application's tree."""
    payload = tmp / "payload"
    for d in ("usr/lib/udev/rules.d", "usr/lib/sysusers.d", "usr/lib/mime/packages"):
        (payload / d).mkdir(parents=True, exist_ok=True)
        (payload / d / "conf").write_bytes(b"data")
    reloc = layout.relocate(payload, tmp / "br")
    assert reloc.private_prefixes == [], reloc.private_prefixes


def test_debian_only_trees_are_dropped(tmp: Path):
    """lintian, bug and apport data have no Fedora counterpart."""
    payload = tmp / "payload"
    for f in ("usr/share/lintian/overrides/app", "usr/share/bug/app/control",
              "usr/share/apport/package-hooks/app.py", "usr/lib/mime/packages/app"):
        p = payload / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    (payload / "usr/bin").mkdir(parents=True)
    (payload / "usr/bin/app").write_bytes(b"\x7fELF")

    reloc = layout.relocate(payload, tmp / "br")
    assert reloc.files == ["/usr/bin/app"], reloc.files
    # dropped lists directories as well as files
    for gone in ("/usr/share/lintian/overrides/app",
                 "/usr/share/bug/app/control",
                 "/usr/share/apport/package-hooks/app.py",
                 "/usr/lib/mime/packages/app"):
        assert gone in reloc.dropped, gone


# =====================================================================
# Strategy B: bundling a library the host cannot provide.
#
# The original design used an LD_LIBRARY_PATH wrapper. That variable is
# inherited across the whole execve tree, so an application spawning
# xdg-open or a browser forces its bundled libraries onto them. Debian's
# own wiki discourages it for exactly this reason. The path is baked into
# the binary instead.
# =====================================================================


def test_bundle_uses_rpath_not_runpath():
    """RUNPATH resolves only the object carrying it, not that object's
    own dependencies. Bundled libraries have dependencies, so RUNPATH
    resolves the first level and fails on the second."""
    import inspect as _inspect

    from debfed import bundle

    source = _inspect.getsource(bundle.apply_bundle)
    assert "--force-rpath" in source, "patchelf writes RUNPATH without this"


def test_bundle_paths_are_relocatable():
    import inspect as _inspect

    from debfed import bundle

    assert "$ORIGIN" in _inspect.getsource(bundle.apply_bundle)


def test_bundle_refuses_non_library_capabilities(tmp: Path):
    """A private prefix cannot supply a file path or an interpreter."""
    from debfed.bundle import plan_bundle

    (tmp / "br").mkdir()
    plan = plan_bundle("app", ["/usr/bin/python3", "some-package"], tmp / "br")
    assert plan.unresolved == ["/usr/bin/python3", "some-package"]
    assert not plan.viable


def test_bundle_reports_unfindable_library(tmp: Path):
    from debfed.bundle import plan_bundle

    (tmp / "br").mkdir()
    plan = plan_bundle("app", ["libnowhere.so.3()(64bit)"], tmp / "br")
    assert plan.unresolved == ["libnowhere.so.3()(64bit)"]


def test_soname_extraction():
    from debfed.bundle import soname_of

    assert soname_of("libcurl.so.4(CURL_OPENSSL_4)(64bit)") == "libcurl.so.4"
    assert soname_of("libfoo.so.1()(64bit)") == "libfoo.so.1"
    assert soname_of("/usr/bin/bash") is None
    assert soname_of("rtld(GNU_HASH)") is None


# =====================================================================
# glibc skew must be decidable without repository access.
# =====================================================================


def test_glibc_skew_is_detected_without_dnf():
    """A binary requiring GLIBC_2.43 cannot run on a 2.39 host whatever
    any repository contains. Deriving this from the unsatisfied list
    meant --offline silently accepted packages that could never start."""
    from debfed.depsolve import max_required_glibc

    reqs = [
        "libc.so.6(GLIBC_2.38)(64bit)",
        "libm.so.6(GLIBC_2.43)(64bit)",
        "libc.so.6(GLIBC_2.17)(64bit)",
    ]
    assert max_required_glibc(reqs) == (2, 43)


def test_glibc_from_other_architectures_is_ignored():
    """32-bit and foreign-arch symbols have their own lower namespaces."""
    from debfed.depsolve import max_required_glibc

    assert max_required_glibc(["libc.so.6(GLIBC_2.4)"]) is None
    assert max_required_glibc([]) is None


# =====================================================================
# Symbol-version-only misses are a naming artifact, not a broken ABI.
# =====================================================================


def test_symbol_version_only_is_classified_separately():
    """Debian added CURL_OPENSSL_3/4 to libcurl during its libcurl3->4
    transition; upstream curl exports unversioned symbols and Fedora
    ships the upstream style. The ABI is identical."""
    res = Resolution(
        satisfied={"libcurl.so.4()(64bit)": ["libcurl"],
                   "libgtk-3.so.0()(64bit)": ["gtk3"]},
        unsatisfied=["libcurl.so.4(CURL_OPENSSL_4)(64bit)",
                     "libgone.so.9()(64bit)"],
    )
    assert res.symbol_version_only == ["libcurl.so.4(CURL_OPENSSL_4)(64bit)"]


def test_corpus_harness_refuses_when_debfed_cannot_run():
    """A harness that cannot invoke debfed must not report results.

    corpus.py counted exit 1 as "refused", so a failed invocation produced
    "refused 54 100%" -- a plausible-looking distribution from a run in
    which nothing executed. This is the same fail-open the exploit suite
    had; both now share tests/_cli.py so the fix cannot apply to one and
    not the other.
    """
    from unittest import mock

    sys.path.insert(0, str(Path(__file__).parent))
    import corpus

    corpus._INVOCATION[:] = ["debfed"]

    # exit 2 means debfed could not reach a verdict, never "refused"
    failed = subprocess.CompletedProcess([], returncode=2, stdout="",
                                         stderr="error: dnf not found")
    with mock.patch("corpus.subprocess.run", return_value=failed):
        with pytest.raises(corpus.CliUnavailable):
            corpus._debfed("inspect", "x.deb")

    # so does an import failure, whatever the exit code
    broken = subprocess.CompletedProcess([], returncode=1, stdout="",
                                         stderr="No module named debfed")
    with mock.patch("corpus.subprocess.run", return_value=broken):
        with pytest.raises(corpus.CliUnavailable):
            corpus._debfed("inspect", "x.deb")

    # a real verdict is passed through untouched
    refused = subprocess.CompletedProcess([], returncode=1, stdout="[]",
                                          stderr="error: base package")
    with mock.patch("corpus.subprocess.run", return_value=refused):
        assert corpus._debfed("inspect", "x.deb").returncode == 1


def test_corpus_harness_refuses_an_empty_corpus(tmp: Path):
    """Measuring nothing is not a passing measurement."""
    import shutil as _shutil

    work = tmp / "harness"
    _shutil.copytree(Path(__file__).parent, work,
                     ignore=_shutil.ignore_patterns("__pycache__", "debs",
                                                    "rpms", "root"))
    proc = subprocess.run([sys.executable, str(work / "corpus.py"), "measure"],
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 2
    assert "no packages" in proc.stdout + proc.stderr


def test_both_harnesses_share_one_invocation_resolver():
    """The pipx bug was fixed in the exploit suite and not the corpus
    harness. Sharing the resolver is what stops that recurring."""
    import inspect as _inspect

    sys.path.insert(0, str(Path(__file__).parent))
    import attack_suite
    import corpus

    assert "_cli" in _inspect.getsource(corpus)
    assert "_cli" in _inspect.getsource(attack_suite)


# =====================================================================
# A missing symbol version is not always fatal.
#
# glibc's dl-version.c returns success with only a "no version
# information available" warning when the provider defines no symbol
# versions at all. It fails only when the provider HAS a version table
# that lacks the required entry. Treating every version miss as fatal
# sends packages to a private prefix to satisfy a label the dynamic
# linker does not enforce.
# =====================================================================


def test_version_definitions_are_detected(tmp: Path):
    from debfed.elf import find_system_library, has_version_definitions

    libc = find_system_library("libc.so.6")
    assert libc is not None, "no libc on this host?"
    # glibc is heavily versioned on every GNU system
    assert has_version_definitions(libc) is True

    (tmp / "notelf").write_bytes(b"#!/bin/sh\n")
    assert has_version_definitions(tmp / "notelf") is None


def test_cosmetic_version_miss_does_not_force_bundling(monkeypatch):
    """The provider defines no versions: the linker warns and continues."""
    import debfed.depsolve as d

    monkeypatch.setattr(d, "find_system_library", lambda s: Path("/fake/lib.so"))
    monkeypatch.setattr(d, "has_version_definitions", lambda p: False)

    res = Resolution(
        satisfied={"libfoo.so.1()(64bit)": ["foo"]},
        unsatisfied=["libfoo.so.1(DISTRO_2)(64bit)"],
    )
    assert res.cosmetic_version_misses == ["libfoo.so.1(DISTRO_2)(64bit)"]
    assert res.blocking_unsatisfied == []


def test_real_version_miss_still_blocks(monkeypatch):
    """The provider HAS a version table lacking the entry: the load fails."""
    import debfed.depsolve as d

    monkeypatch.setattr(d, "find_system_library", lambda s: Path("/fake/lib.so"))
    monkeypatch.setattr(d, "has_version_definitions", lambda p: True)

    res = Resolution(
        satisfied={"libfoo.so.1()(64bit)": ["foo"]},
        unsatisfied=["libfoo.so.1(DISTRO_2)(64bit)"],
    )
    assert res.cosmetic_version_misses == []
    assert res.blocking_unsatisfied == ["libfoo.so.1(DISTRO_2)(64bit)"]


def test_unknown_provider_is_treated_as_blocking(monkeypatch):
    """If the library cannot be found, assume the miss is real."""
    import debfed.depsolve as d

    monkeypatch.setattr(d, "find_system_library", lambda s: None)
    res = Resolution(
        satisfied={"libfoo.so.1()(64bit)": ["foo"]},
        unsatisfied=["libfoo.so.1(DISTRO_2)(64bit)"],
    )
    assert res.blocking_unsatisfied == ["libfoo.so.1(DISTRO_2)(64bit)"]


def test_cosmetic_misses_yield_strategy_a(tmp: Path, monkeypatch):
    import debfed.depsolve as d

    monkeypatch.setattr(d, "find_system_library", lambda s: Path("/fake/lib.so"))
    monkeypatch.setattr(d, "has_version_definitions", lambda p: False)

    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": b"\x7fELF"})
    dd = unpack(deb, tmp / "w")
    res = Resolution(
        requires=["libfoo.so.1()(64bit)", "libfoo.so.1(DISTRO_2)(64bit)"],
        satisfied={"libfoo.so.1()(64bit)": ["foo"]},
        unsatisfied=["libfoo.so.1(DISTRO_2)(64bit)"],
    )
    a = assess(dd, _empty_reloc(tmp), res)
    assert a.verdict is Verdict.STRATEGY_A, a.reason
    assert "symbol-version" in a.reason


# =====================================================================
# Host runtime contract.
#
# A .deb declares package dependencies. It does not declare what it
# assumes about the running system -- that unprivileged user namespaces
# work, that a session bus exists, that a display is reachable. Those
# assumptions are invisible to dependency resolution and are where a
# correctly-converted package still fails to start.
# =====================================================================


def test_userns_probe_prefers_the_distribution_specific_sysctl(monkeypatch):
    """kernel.unprivileged_userns_clone is a Debian/Ubuntu/Arch patch and
    does not exist upstream; Fedora exposes user.max_user_namespaces."""
    from debfed import runtime

    values = {}
    monkeypatch.setattr(runtime, "_read_int", lambda p: values.get(p))

    values.clear()
    values["/proc/sys/user/max_user_namespaces"] = 15000
    assert runtime.user_namespaces().available is True

    values.clear()
    values["/proc/sys/user/max_user_namespaces"] = 0
    assert runtime.user_namespaces().available is False

    values.clear()
    values["/proc/sys/kernel/unprivileged_userns_clone"] = 0
    assert runtime.user_namespaces().available is False


def test_ubuntu_apparmor_restriction_blocks_namespaces(monkeypatch):
    """Ubuntu 23.10+ restricts namespaces through AppArmor even when the
    kernel permits them."""
    from debfed import runtime

    values = {
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": 1,
        "/proc/sys/user/max_user_namespaces": 15000,
    }
    monkeypatch.setattr(runtime, "_read_int", lambda p: values.get(p))
    ns = runtime.user_namespaces()
    assert ns.available is False
    assert ns.mechanism == "apparmor"


def test_dropped_sandbox_setuid_is_fine_with_namespaces(monkeypatch):
    """With user namespaces available the helper is unnecessary at 0755.

    A pre-emptive failure on the missing bit would break working installs.
    """
    from debfed import runtime

    monkeypatch.setattr(runtime, "user_namespaces",
                        lambda: runtime.UserNamespaces(True, "test", "ok"))
    severity, _ = runtime.sandbox_outlook(has_setuid_helper=True,
                                          setuid_preserved=False)
    assert severity == "ok"


def test_dropped_sandbox_setuid_is_fatal_without_namespaces(monkeypatch):
    """With no namespaces the helper is the only sandbox; Chromium aborts
    before opening a window."""
    from debfed import runtime

    monkeypatch.setattr(runtime, "user_namespaces",
                        lambda: runtime.UserNamespaces(False, "test", "blocked"))
    severity, explanation = runtime.sandbox_outlook(has_setuid_helper=True,
                                                    setuid_preserved=False)
    assert severity == "fatal"
    assert "--no-sandbox" in explanation


def test_package_without_a_sandbox_helper_is_unaffected(monkeypatch):
    from debfed import runtime

    monkeypatch.setattr(runtime, "user_namespaces",
                        lambda: runtime.UserNamespaces(False, "test", "blocked"))
    severity, _ = runtime.sandbox_outlook(has_setuid_helper=False,
                                          setuid_preserved=False)
    assert severity == "ok"


def test_host_probe_is_read_only():
    """Nothing in the probe may modify the system."""
    import inspect as _inspect

    from debfed import runtime

    source = _inspect.getsource(runtime)
    for forbidden in ("write_text(", "os.chmod", "subprocess.run",
                      "sysctl -w", "os.remove"):
        assert forbidden not in source, f"probe performs {forbidden}"


# =====================================================================
# The analysis must reach the generated package.
#
# rpmbuild runs its own dependency generator over the buildroot and
# knows nothing about what inspect concluded. Without explicit
# exclusions the package requires every capability the analysis already
# established is bogus, so the verdict says "converts cleanly" while dnf
# refuses to install it.
# =====================================================================


def test_capability_patterns_avoid_parentheses():
    """Escaped parens do not survive rpm's macro expansion.

    An exclusion written with \\( \\) silently fails to match, while the
    same pattern using '.' wildcards works. Measured against rpmbuild.
    """
    from debfed.spec import _cap_pattern

    for cap in ("libfoo.so.1()(64bit)", "libcurl.so.4(CURL_OPENSSL_4)(64bit)"):
        pattern = _cap_pattern(cap)
        assert "(" not in pattern, pattern
        assert ")" not in pattern, pattern


def test_capability_pattern_matches_what_it_should():
    import re as _re

    from debfed.spec import _cap_pattern

    versioned = _cap_pattern("libcurl.so.4(CURL_OPENSSL_4)(64bit)")
    assert _re.match(versioned, "libcurl.so.4(CURL_OPENSSL_4)(64bit)")
    # the bare soname must survive, so dnf still pulls the library in
    assert not _re.match(versioned, "libcurl.so.4()(64bit)")

    bare = _cap_pattern("libffmpeg.so()(64bit)")
    assert _re.match(bare, "libffmpeg.so()(64bit)")


def test_spec_excludes_foreign_architecture_binaries(tmp: Path):
    deb = make_deb(tmp, "mixed", "1.0-1", {
        "usr/share/mixed/prog": _elf(0x3E),
        "usr/share/mixed/vendor/arm64/helper": _elf(0xB7),
    })
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    res = Resolution(foreign={"aarch64": [
        str(reloc.buildroot / "usr/share/mixed/vendor/arm64/helper")]})
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A",
                          resolution=res)
    text = spec.render(plan, reloc.buildroot)
    assert "__requires_exclude_from" in text
    assert "/usr/share/mixed/vendor/arm64/helper" in text


def test_spec_excludes_self_provided_and_cosmetic_capabilities(tmp: Path):
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": _elf(0x3E)})
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    res = Resolution(
        self_satisfied=["libffmpeg.so()(64bit)"],
        satisfied={"libcurl.so.4()(64bit)": ["libcurl"]},
        unsatisfied=["libcurl.so.4(CURL_OPENSSL_4)(64bit)"],
    )
    # force the cosmetic classification without touching the host
    res.__dict__["_cosmetic"] = True
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A",
                          resolution=res)
    text = spec.render(plan, reloc.buildroot)
    assert "__requires_exclude" in text
    assert "libffmpeg" in text


def test_plan_spec_without_resolution_emits_no_exclusions(tmp: Path):
    """Callers that omit the resolution get the unfiltered behaviour,
    which is wrong but must not crash."""
    deb = make_deb(tmp, "app", "1.0-1", {"usr/bin/app": _elf(0x3E)})
    d = unpack(deb, tmp / "w")
    reloc = layout.relocate(d.payload_dir, tmp / "br")
    plan = spec.plan_spec(d, reloc, analyse_scripts({}, [], SAFE_TRIGGERS), "A")
    text = spec.render(plan, reloc.buildroot)
    assert "__requires_exclude_from" not in text
