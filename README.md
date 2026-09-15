# debfed

Install vendor-distributed `.deb` applications on Fedora as **native RPMs** — owned by rpm, visible to `rpm -qa`, removable with `dnf`, with a real desktop entry and a real `PATH` binary.

No Distrobox. No Podman. No chroot. No VM.

```console
$ debfed install claude-desktop_1.2.3_amd64.deb
```

---

## Install

### From a release (recommended)

```bash
sudo dnf install https://github.com/USER/debfed/releases/latest/download/debfed-0.1.0-1.fc44.noarch.rpm
```

### From COPR

```bash
sudo dnf copr enable USER/debfed
sudo dnf install debfed
```

### From source

```bash
git clone https://github.com/USER/debfed
cd debfed
sudo dnf install rpm-build python3-pyyaml
pip install --user -e .
```

**Requires:** Fedora 41+, x86_64, `rpm-build` (for `rpmdeps`), `python3-pyyaml`. On Python below 3.14 you also need the `zstd` binary, since modern `.deb` payloads are zstd-compressed and `tarfile` only learned zstd in 3.14.

---

## Use

```bash
debfed inspect app.deb            # what it needs, which strategy, what fails
debfed inspect --json app.deb     # machine-readable
debfed build app.deb -o ./out     # produce an RPM, install nothing
debfed build --spec-only app.deb  # print the generated spec
debfed install app.deb            # dry run, then confirm, then dnf install
debfed install --dry-run app.deb  # stop after the dry run
debfed remove app                 # delegates to dnf
debfed map list                   # view the dependency mapping database
debfed map add fonts-foo foo-fonts
```

`install` **always** prints a dnf transaction preview and waits for confirmation. `-y` skips the prompt; it does not skip the preview.

---

## Scope

**Works** — vendor-distributed applications: Electron apps, static Go/Rust binaries, self-contained GUI and CLI tools. Chrome, VS Code, Claude Desktop, Slack, Discord, Obsidian, 1Password, Zoom, Postman.

**Refused, with a named reason** —

| Refusal | Why it is not fixable |
|---|---|
| Base system packages (`libc6`, `systemd`, `coreutils`) | Ships files Fedora's own packages own; forcing it is unrecoverable |
| Payload needs a **newer** glibc than the host | Bundling glibc requires a matching `ld.so`; out of scope |
| Would require bundling a toolkit (GTK, Qt, NSS, mesa) | `LD_LIBRARY_PATH` prefixing breaks the moment the app `dlopen`s a host module |
| Kernel modules, DKMS, initramfs, bootloader | Built against Debian's kernel |
| `dpkg-divert`, unknown triggers, debconf, `Pre-Depends` | No rpm semantics exist; emulating them means maintaining a shadow dpkg database |

**Known limitation — self-referential library packages.** If a Debian
package's binary links a library that Fedora ships *inside the
same-named package*, the conversion is unsatisfiable: the converted
`jq` requires `libjq.so.1`, whose only Fedora provider is Fedora's own
`jq`, which conflicts by name. debfed builds the RPM successfully but
`dnf` cannot install it. This affects tools that ship their own library
alongside the binary; vendor applications, which bundle their libraries
privately, are unaffected.

**debfed is not a general Debian-to-Fedora converter.** For the refused cases, use Distrobox — that is exactly what containers are for.

---

## How it works

The usual approach to this problem is to translate Debian's `Depends:` field into Fedora package names. That approach is why `alien` has never worked well: package names differ across distributions and the mapping is unbounded.

debfed **discards `Depends:` entirely** and runs rpm's own ELF dependency generator over the payload instead:

```console
$ /usr/lib/rpm/rpmdeps --requires ./usr/bin/jq
libc.so.6()(64bit)
libc.so.6(GLIBC_2.38)(64bit)
libjq.so.1()(64bit)
rtld(GNU_HASH)
```

That is verbatim Fedora capability syntax, generated from a Debian-built binary. SONAMEs are defined upstream, so they are identical across distributions — unlike package names. Fedora's `glibc` provides every `GLIBC_*` up to its own version; `jq-libs` provides `libjq.so.1()(64bit)`. `dnf` resolves the rest.

The shipped mapping database therefore covers only what ELF cannot express: fonts, icon themes, and helper binaries invoked at runtime. About 60 entries, not thousands.

### Pipeline

```
extract (stdlib ar + tarfile)
  ↓
refusal engine ──────────────────► REFUSE, with a reason
  ↓
relocate  /usr/lib/x86_64-linux-gnu → /usr/lib64
  ↓
rpmdeps --requires over the buildroot
  ↓
dnf repoquery --whatprovides (each capability)
  ↓
  all satisfied      → Strategy A: translate to RPM
  leaf libs missing  → Strategy B: private prefix under /opt/debfed
  toolkit or glibc   → REFUSE
  ↓
render spec → rpmbuild → dnf install --assumeno (dry run) → dnf install
```

### Three things that are easy to get wrong

**Directory ownership.** A generated spec must never claim `/usr/bin`, `/usr/share/applications`, or any other directory owned by Fedora's `filesystem` package. Claiming them is precisely what makes `alien` output refuse to install with `file /usr/bin from install of X conflicts with file from package filesystem`. debfed owns files, and owns directories only under its own prefix.

**Provides leakage.** An Electron app bundles `libffmpeg.so`, `libEGL.so`, `libGLESv2.so`. Without filtering, the generated RPM advertises those to the entire system and dnf may satisfy unrelated packages from inside your app. Every private prefix gets `%global __provides_exclude_from`.

**Binary post-processing.** `brp-strip` will strip vendor binaries, `brp-mangle-shebangs` will rewrite interpreters, and debuginfo extraction will fail on prebuilt payloads. All disabled in every generated spec.

---

## Safety

See [SECURITY.md](SECURITY.md) for the threat model and the list of
vulnerabilities found and fixed during pre-release review.

Every byte of a `.deb` is attacker-controlled, and debfed usually runs under
sudo. The bar is that processing a malicious package must not execute its
code or write outside the working directory — including during `inspect` and
`build`, which install nothing.

- Maintainer scripts are **never executed**; they are parsed, and only a
  known-safe subset becomes rpm scriptlets.
- All `.deb`-derived values are escaped before entering a spec. rpm expands
  `%(shell command)` at parse time, so this is the difference between a
  converter and a remote code execution primitive.
- No on-disk path is derived from an untrusted package name.
- Extraction uses tarfile's `data` filter with symlinks deferred to a second
  pass, so no archive member can be written through a link.
- Decompression-bomb limits on member size, unpacked size and entry count.
- No `shell=True` anywhere in the codebase.
- Read-only inspection first; `inspect` and `build` never touch the system.
- Mandatory dnf dry-run before any install.
- File-conflict detection against installed RPMs, with a clearer message than rpm's.
- Path-traversal guard on payload extraction.
- No code path copies into `/usr`. Everything goes through rpm.
- Maintainer scripts are never executed. They are parsed; a known-safe subset is translated into scriptlets and the rest is logged and skipped.

---

## Development

```bash
python -m pytest tests/ -v        # unit and regression tests
python tests/attack_suite.py      # live exploit suite
ruff check src/ tests/            # lint
bandit -r src/ -ll                # static analysis
```

Tests requiring `rpmbuild` skip automatically when it is absent.

### CI gates

Every push runs `.github/workflows/checks.yml`. A tagged release runs the
**identical** set first and will not produce an RPM unless all of it passes
— `release.yml`'s build job declares `needs: checks`.

| Gate | What it catches |
|---|---|
| `lint` | ruff, formatting |
| `typecheck` | mypy |
| `sast` | bandit, failing on medium severity and above |
| `dependency-audit` | pip-audit against the declared dependency set |
| `secrets` | gitleaks over full history |
| `test` | full suite on two Fedora releases |
| `exploit-suite` | nine live exploits run against the real CLI |
| `package-integrity` | converts a real `.deb`; asserts no `filesystem`-owned directory is claimed, SONAME requires exist, no bundled library provide leaks, the RPM installs and removes cleanly, and `libc6` is refused |
| `gate` | single required status aggregating all of the above |

CodeQL with `security-extended` runs separately and reports to the
repository's Security tab.

The release build additionally re-runs the exploit suite against the
**installed** package rather than the working tree, verifies the tag matches
`__version__`, and publishes `SHA256SUMS`.

---

## Prior art

- **alien** — converts the format, ignores dependency mapping and paths.
- **debtap** — Arch; resolves via `pkgfile`, the closest conceptual reference.
- **fpm** — a build tool for producing packages, not for converting foreign ones onto a host.
- **Distrobox** — the container answer, and the right answer for everything debfed refuses.

---

## Licence

MIT
