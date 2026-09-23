# debfed

Install Debian `.deb` applications on Fedora as native RPMs.

The application lands in the host system — a real desktop entry, a real
binary on `PATH`, real `rpm`/`dnf` ownership. No container, no chroot,
no VM.

```bash
debfed install app.deb
```

or double-click a `.deb` in Files.

---

## Read this first

**Converting a package is not the same as trusting it.** A `.deb` is an
archive from the internet. debfed makes it installable; it does not make
it safe. Install packages from vendors you would already trust with
`sudo`.

**Installing a converted package is exactly as privileged as
`sudo dnf install`.** The payload lands as root-owned files anywhere
under `/usr`. debfed never executes the package's maintainer scripts,
which removes one large class of risk, but the files themselves are
still installed as root.

**This is not a substitute for a Fedora package.** If the software is in
Fedora, RPM Fusion or a COPR, use that. Those builds are compiled
against Fedora's libraries and receive security updates through dnf. A
converted package receives whatever the vendor pushes.

**It refuses things it cannot convert correctly, and that is the tool
working.** It names the library or property that makes conversion
impossible rather than producing something that installs and then fails.

---

## Measured results

### Vendor applications — what this tool is for

Resolved against live Fedora 44 repositories:

| Application | Verdict | |
|---|---|---|
| Google Chrome | A | converts, builds, installs |
| Claude Desktop | A | converts, builds, installs |
| Discord | A | converts, builds, installs |
| Obsidian | A | converts, builds, installs |
| VSCodium | A | converts, builds, installs |

**5 of 5**, no refusals, and none claims a directory owned by another
package. Chrome was installed, run, and removed together with the
thirteen dependencies dnf pulled in for it.

```bash
python3 tests/corpus.py fetch-vendor
python3 tests/corpus.py vendor
```

This is held to a stricter standard than the sample below: a vendor
application that fails to convert is a failure, not a statistic.

### Distribution packages — a deliberate stress test

A sample of 54 Ubuntu archive packages: GUI applications, command-line
tools, daemons, fonts, games, browsers, libraries.

| Outcome | Count | |
|---|---|---|
| Converts | 40 | 74% |
| Refused | 14 | 26% |

| Cause | Count | Why |
|---|---|---|
| `UNOBTAINABLE` | 10 | a library is neither on Fedora nor inside the package |
| `BASE_PACKAGE` | 3 | bash, dbus, systemd — replacing these is unrecoverable |
| `TOOLKIT_GAP` | 2 | GTK/Qt/mesa/NSS cannot be bundled privately |
| `GLIBC_SKEW` | 1 | needs a newer glibc than the host has |
| `SYSTEM_PATH` | 1 | writes into a boot or kernel path |

The two populations differ for a structural reason. Distribution
packages depend on *other distribution packages*, so a quarter of them
name a library Fedora does not carry and are correctly refused. Vendor
applications bundle their own libraries, which is why they convert at a
far higher rate. **The 74% figure understates the tool for its actual
use**; it is kept because a hard sample finds bugs an easy one does not.

```bash
python3 tests/corpus.py fetch
python3 tests/corpus.py measure
python3 tests/corpus.py run      # installs each one and executes it
```

---

## How it works

**Debian's `Depends:` field is discarded entirely.** Package names do not
translate across distributions, and mapping them is a list that is never
finished — which is why `alien` has never worked properly.

Instead, rpm's own dependency generator runs over the payload. It emits
capabilities in Fedora's own syntax, derived from the SONAMEs compiled
into the binaries:

```
libgtk-3.so.0()(64bit)
libc.so.6(GLIBC_2.38)(64bit)
```

SONAMEs are set upstream and are identical on every distribution, so
they resolve natively. On VSCodium, 131 of 135 capabilities resolved
this way with no mapping entries at all. The shipped mapping database
covers only what ELF cannot express — fonts, `xdg-utils`, runtime
helpers — about sixty entries, not thousands.

Two strategies, chosen per package:

- **A — translate to RPM.** Every requirement resolves against Fedora.
- **B — private prefix.** A library the host lacks is bundled under
  `/opt/debfed/<app>/lib` and the binaries are re-pointed at it with
  `patchelf --force-rpath`. Only possible when the package ships that
  library itself.

**Strategy B has not been needed by any package tested so far** — 0 of
59. Vendor applications keep their private libraries under `/opt` or
`/usr/share`, where provides-filtering already keeps them internal, and
distribution packages want libraries that live in other packages, which
a private prefix cannot supply. Treat it as the less-exercised path.

---

## What gets changed, and why

| Debian | Fedora | Reason |
|---|---|---|
| `/usr/lib/x86_64-linux-gnu` | `/usr/lib64` | different multiarch layout |
| `/usr/share/lintian`, `bug`, `apport` | dropped | no Fedora counterpart |
| `/etc/apparmor.d/*` | dropped | Fedora uses SELinux; a profile here is never loaded |
| apt repository registration | stripped | meaningless on Fedora |
| `update-alternatives` | stripped | no equivalent |
| launcher created in `postinst` | shipped in `%files` | so rpm owns and removes it |
| systemd units | kept, registered, **not enabled** | Fedora presets decide what starts |

**Directories are owned by an allowlist.** A package may own only
directories inside its own tree. Everything else is left unowned. A
54-package sample claimed 155 shared directories — `/usr/share/locale`
alone has hundreds of subdirectories — and claiming them is precisely
what makes `alien` output conflict with `filesystem`, `systemd` and
`glibc-langpack`.

---

## Warnings you may see

**`DOWNLOADER`** — the package contains a launcher, not the program. On
first run it downloads the real application into your home directory and
runs that. Discord works this way. Consequences: rpm cannot verify what
actually runs, removing the package leaves the downloaded copy behind in
`~/.config`, and the application updates itself without dnf. Not caused
by the conversion and not fixable here.

**`SYMBOL_VERSION`** — a capability differs only by a distribution
symbol label. Debian adds its own symbol versions to some libraries
whose ABI is unchanged; `libcurl` is the known case, where upstream
exports unversioned symbols and Debian added `CURL_OPENSSL_4`. When the
provider defines no symbol versions at all, the dynamic linker warns and
continues, so these are not real incompatibilities. 13 of 54 sample
packages carry one.

**`SANDBOX`** — the package ships a setuid `chrome-sandbox` helper and
the bit was dropped during extraction. Harmless where unprivileged user
namespaces are available, because Chromium uses the namespace sandbox
instead. Where they are not, the application aborts before opening a
window; debfed checks your host and says which case applies.

**`DEBCONF_PROMPT`** — the package asks a configuration question during
install. debfed does not run maintainer scripts, so the default answer
applies, exactly as with `DEBIAN_FRONTEND=noninteractive`. The question
is named so you can judge whether the default matters.

**`TRIGGERS`** — a dpkg trigger has no rpm equivalent, so one refresh
action will not run. A degradation, not a hazard.

**`SHARED_DIRS`** — directories owned by Fedora base packages were
excluded from `%files`. This is deliberate and is what keeps the package
installable.

---

## Known limitations

- **GNOME Shell search providers are lost.** Some packages install them
  from `postinst`, which is discarded. The application works; it will
  not appear in Shell search.
- **Unversioned symbol mismatches are invisible.** If a library has the
  right SONAME but lacks a function the binary needs, dependency
  resolution cannot see it — the failure appears at launch.
- **Interpreted-language dependencies are unmapped.** Perl, Python and
  Ruby module requirements are not translated.
- **Self-referential library packages cannot be converted.** A package
  whose only provider of its own library is the Fedora package of the
  same name creates an unsatisfiable conflict.
- **x86_64 only.** Binaries for other architectures inside a package are
  detected and excluded from dependency scanning, but are still shipped.

---

## Installing

From the latest release:

```bash
sudo dnf install \
  https://github.com/Marvin1198/debfed/releases/download/v0.1.0/debfed-0.1.0-1.fc44.noarch.rpm
```

Each release ships a `SHA256SUMS` alongside the package.

Install as an RPM rather than with pip or pipx if you want the
file-manager integration: the privileged helper and its polkit action
are part of the package and are not installed any other way.

### From source

```bash
sudo dnf install -y \
  git make rpm-build rpmdevtools pyproject-rpm-macros desktop-file-utils \
  python3-devel python3-setuptools python3-pytest python3-pyyaml \
  patchelf zenity

git clone https://github.com/Marvin1198/debfed
cd debfed
make rpm
sudo dnf install ~/rpmbuild/RPMS/noarch/debfed-*.rpm
```

The build runs the full test suite in `%check`, so it fails rather than
producing a package that does not work.

---

## Usage

```bash
debfed inspect app.deb          # read-only; writes nothing
debfed inspect -v app.deb       # adds the host runtime report
debfed build   app.deb -o DIR   # produce an RPM, install nothing
debfed install app.deb          # convert, show the transaction, install
debfed remove  <name>           # dnf remove
debfed map     list|get|add|remove   # dependency mapping database
```

`--strict-scripts` refuses any package whose maintainer scripts ask a
debconf question, instead of warning. It works before or after the
subcommand.

Exit codes: `0` success, `1` a verdict about the package (refused, or
you declined), `2` debfed could not decide (a tool is missing, the file
is unreadable).

---

## Double-clicking a package

debfed registers as a handler for
`application/vnd.debian.binary-package`. Opening one in a file manager:

1. converts it **as you**, with no privileges — this needs none
2. shows the full report, with Convert and Cancel
3. escalates once through polkit, which presents the system's own
   authentication dialog

The report is shown before anything is installed. That is the point of
the tool and is not traded away for convenience.

**debfed never handles your password.** Only `pkexec` does, and it
reports nothing back but whether authorisation succeeded. An application
that collects the password itself is indistinguishable from a phishing
dialog, whatever its title bar says.

Conversion takes about twenty seconds for a large Electron application,
and a progress dialog is shown throughout. A package that downloads
itself on first run — see `DOWNLOADER` above — may then spend several
more minutes fetching, which debfed neither controls nor reports.

---

## Security

`debfed-install` is the only component that ever runs as root. It takes
one absolute path, verifies the RPM magic bytes and calls dnf. It will
not accept a `.deb`, a spec, a script or a command, and uses no shell.

The polkit action requires administrator authentication in every mode
and is never cached. Both the test suite and the package build fail if
that is ever relaxed — a permissive polkit rule on a package-install
action is CVE-2026-41651, where any local user could install an
arbitrary RPM without a password and its `%post` ran as root.

Maintainer scripts are never executed. Only a known-safe subset —
`ldconfig`, desktop database, icon cache, MIME database — is translated
into rpm scriptlets. Everything else is discarded.

Values taken from the `.deb` are escaped before reaching the spec file,
because rpm expands `%(command)` through `/bin/sh` at parse time. A live
exploit suite runs nine attacks against the real CLI on every build.

See `SECURITY.md` for the full list of findings and fixes.

---

## Reporting a problem

Include the output of:

```bash
debfed inspect -v <package>.deb
```

It contains the verdict, every capability and how it resolved, the
maintainer-script analysis and your host's runtime configuration.

---

## Licence

MIT.
