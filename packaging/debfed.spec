%global pypi_name debfed
%global forgeurl https://github.com/USER/debfed

Name:           debfed
Version:        0.1.0
Release:        1%{?dist}
Summary:        Install Debian-targeted applications on Fedora as native RPMs

License:        MIT
URL:            %{forgeurl}
Source0:        %{forgeurl}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-pytest
BuildRequires:  desktop-file-utils

# rpmdeps lives in rpm-build and is how debfed reads ELF dependencies.
Requires:       rpm-build
Requires:       python3-pyyaml
Requires:       dnf
# Strategy B rewrites RPATH on bundled binaries.
Requires:       patchelf
# Needed only on Python < 3.14, where tarfile cannot read zstd payloads.
Recommends:     zstd

%description
debfed installs vendor-distributed .deb applications on Fedora as real
RPMs: owned by rpm, visible to rpm -qa, removable with dnf, with a real
desktop entry and a real PATH binary. No container, no chroot, no VM.

It works by discarding the Debian Depends field entirely and letting
rpm's own ELF dependency generator derive requirements from the binaries,
which resolve against Fedora by SONAME. Filesystem paths are translated
from Debian multiarch layout to Fedora's, maintainer scripts are reduced
to a known-safe subset, and bundled libraries are prevented from
advertising themselves system-wide.

debfed is not a general Debian-to-Fedora converter. It refuses base
system packages, kernel modules, and anything depending on dpkg
semantics, and it names the reason rather than half-installing.

%prep
%autosetup -n %{name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files %{pypi_name}

install -Dpm 0644 packaging/debfed.1 %{buildroot}%{_mandir}/man1/debfed.1

# Register debfed as a handler for .deb files, so a package can be opened
# from a file manager. The MIME type is IANA-registered and already known
# to shared-mime-info, so no private MIME definition is installed.
desktop-file-install \
    --dir=%{buildroot}%{_datadir}/applications \
    packaging/debfed.desktop

%check
%pytest tests/ -q
desktop-file-validate %{buildroot}%{_datadir}/applications/debfed.desktop

%post
update-desktop-database &>/dev/null || :

%postun
update-desktop-database &>/dev/null || :

%files -f %{pyproject_files}
%doc README.md SECURITY.md
%license LICENSE
%{_bindir}/debfed
%{_datadir}/applications/debfed.desktop
%{_mandir}/man1/debfed.1*

%changelog
* Mon Sep 14 2026 debfed maintainers <debfed@example.com> - 0.1.0-1
- Initial package
- inspect, build, install, remove and map subcommands
- SONAME-based dependency resolution via rpmdeps
- Refusal engine for base packages, kernel paths and dpkg-only semantics
