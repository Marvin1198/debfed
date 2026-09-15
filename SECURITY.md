# Security

## Threat model

debfed processes `.deb` files from vendor websites. **Every byte of a `.deb`
is attacker-controlled**: control fields, file paths, symlink targets,
maintainer scripts, member sizes, compression ratios. A user who downloads
the wrong file, or a vendor whose CDN is compromised, hands debfed hostile
input.

debfed usually runs as root or under sudo. The bar is therefore: *processing
a malicious `.deb` must not execute its code or write outside the working
directory* — including during `inspect` and `build`, which install nothing
and are reasonably assumed safe.

## Design decisions

**Maintainer scripts are never executed.** They are parsed. A known-safe
subset (`ldconfig`, desktop/icon/mime cache refreshes) becomes rpm
scriptlets; everything else is logged and skipped. A `.deb` cannot run code
through debfed at any stage.

**Generated specs escape all untrusted input.** rpm expands `%(shell
command)` through `/bin/sh` and `%{lua:...}` through an embedded interpreter
at spec *parse* time. Every `.deb`-derived value passes through
`sanitize.spec_value`, `spec_text`, `spec_path`, `spec_url` or
`safe_requires` first. Escaping is by doubling every `%`, applied to whole
strings rather than to recognised macro forms — a construct a future rpm
learns to expand is still neutralised.

**No on-disk path is derived from an untrusted name.** The generated spec is
always written to a fixed filename inside a private temporary directory.

**Extraction uses tarfile's `data` filter**, with symlinks deferred to a
second pass. Absolute symlinks are legitimate and ubiquitous in vendor
packages (`/usr/bin/code -> /opt/code/bin/code`), so refusing them outright
would refuse Chrome, VS Code and Claude Desktop. Creating them last means no
archive member can be written through one.

**Relocation re-checks containment.** Every write resolves its parent and
refuses if it lands outside the buildroot, rather than trusting extraction.

**Resource limits** bound decompression bombs: 4 GiB per ar member, 8 GiB
unpacked, 200,000 entries, 64 ar members, 300 s zstd timeout.

**No shell anywhere.** Every subprocess call passes an argument list. There
is no `shell=True` in the codebase.

## Fixed vulnerabilities

Found by adversarial review of this code before first release. Each has a
regression test in `tests/test_debfed.py`.

| # | Severity | Issue |
|---|---|---|
| 1 | **Critical** | Macro injection via `Description`. A crafted field achieved **arbitrary code execution as root** during `debfed build`. Verified: `%(id > /tmp/pwned)` executed. |
| 2 | **Critical** | Same via `Homepage`/`URL`. Hostile URLs are now dropped. |
| 3 | **High** | `Package:` name flowed into the spec's on-disk path. `../../../../tmp/x` wrote a file outside the working directory. |
| 4 | **High** | Extraction used the `tar` filter, which permits a lone absolute symlink; it only catches an escape when a later member writes through one. A hostile symlink reached the built RPM. |
| 5 | **Medium** | `%files` paths were quoted but not escaped, and `%`-containing paths broke the build. Now refused with a stated reason. |
| 6 | **Medium** | No bounds on ar member sizes or unpacked payload size — decompression-bomb DoS. |
| 7 | **Medium** | `find_conflicts` used `rpm -qf`, which stats each argument and writes failures to stderr, so stdout no longer aligned with inputs — the wrong owner was reported for the wrong file. Replaced with rpmdb queries. |
| 8 | **Low** | Bulk rpmdb query split on a space; rpm filenames may contain spaces. Now tab-separated. |
| 9 | **Low** | Truncated ar members were accepted silently. |

## Residual risks

- **The payload is still third-party code.** debfed makes installation
  safe; it does not make the application trustworthy. Verify vendor
  signatures yourself.
- **`.deb` files are not signature-checked.** Individual `.deb` files
  carry no signature in practice; authenticity normally comes from the apt
  repository, which debfed deliberately does not use. Download over HTTPS
  from the vendor and check published hashes.
- **`dnf install` runs vendor scriptlets we generated**, but only the
  translated safe subset.
- **setuid bits are dropped** by the data filter. An app relying on a
  legacy SUID sandbox needs user namespaces instead; debfed warns.

## Reporting

Open a security advisory on the repository rather than a public issue.
