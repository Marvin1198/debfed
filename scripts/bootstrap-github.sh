#!/usr/bin/env bash
#
# Create the public debfed repository and push.
# Read this before running it. Nothing here is irreversible except the
# repo creation itself, which you can delete afterwards.
#
#   ./scripts/bootstrap-github.sh
#
set -euo pipefail

# ---------------------------------------------------------------- config
GH_USER="${GH_USER:-marvin1198}"       # override: GH_USER=youruser ./bootstrap-github.sh
REPO="${REPO:-debfed}"
DESC="Install Debian-targeted applications on Fedora as native RPMs. No container."

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# ------------------------------------------------------- 0. sanity checks
say "Preflight"
command -v git >/dev/null || { echo "git not found"; exit 1; }
command -v gh  >/dev/null || { echo "gh not found: sudo dnf install gh"; exit 1; }
gh auth status || { echo "run: gh auth login"; exit 1; }

test -f pyproject.toml || { echo "run this from the debfed project root"; exit 1; }
test -d .github/workflows || { echo "workflows missing"; exit 1; }

say "Local verification before anything is published"
python -m pytest tests/ -q
python tests/attack_suite.py
ruff check src/ tests/
echo "local checks passed"

# --------------------------------------------- 1. replace the placeholder
say "Substituting USER -> $GH_USER"
grep -rl 'USER/debfed' --include='*.md' --include='*.spec' --include='*.toml' . \
  | xargs -r sed -i "s|USER/debfed|$GH_USER/debfed|g"
grep -rn "$GH_USER/debfed" README.md pyproject.toml packaging/debfed.spec | head -5

# ------------------------------------------------------ 2. git init/commit
say "Initialising the repository"
if [ ! -d .git ]; then
  git init
  git branch -M main
fi

git add -A
git -c user.name="${GIT_NAME:-$GH_USER}" \
    -c user.email="${GIT_EMAIL:-$GH_USER@users.noreply.github.com}" \
    commit -m "debfed 0.1.0

Install Debian-targeted .deb applications on Fedora as native RPMs,
with no container, chroot or VM.

Dependencies resolve by SONAME through rpm's own ELF dependency
generator rather than by translating Debian package names, which is
why this works where alien does not.

Includes a refusal engine for base packages, kernel modules and
dpkg-only semantics, and a security test suite covering nine live
exploits found during pre-release review (see SECURITY.md)."

# ----------------------------------------------------- 3. create the repo
say "Creating public repository $GH_USER/$REPO"
gh repo create "$GH_USER/$REPO" \
  --public \
  --description "$DESC" \
  --source=. \
  --remote=origin \
  --push

# ------------------------------------------------------ 4. repo metadata
say "Setting topics and features"
gh repo edit "$GH_USER/$REPO" \
  --add-topic fedora \
  --add-topic debian \
  --add-topic rpm \
  --add-topic packaging \
  --add-topic deb \
  --add-topic linux \
  --add-topic python \
  --enable-issues \
  --enable-discussions=false \
  --enable-wiki=false \
  --delete-branch-on-merge

# ------------------------------------------ 5. security features (public)
say "Enabling security features"
gh api -X PATCH "repos/$GH_USER/$REPO" \
  -F security_and_analysis[secret_scanning][status]=enabled \
  -F security_and_analysis[secret_scanning_push_protection][status]=enabled \
  >/dev/null && echo "secret scanning + push protection on" \
  || echo "note: secret scanning may need to be enabled in the web UI"

cat > /tmp/dependabot.yml <<'YAML'
version: 2
updates:
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
YAML
mkdir -p .github
cp /tmp/dependabot.yml .github/dependabot.yml
git add .github/dependabot.yml
git -c user.name="${GIT_NAME:-$GH_USER}" \
    -c user.email="${GIT_EMAIL:-$GH_USER@users.noreply.github.com}" \
    commit -m "ci: dependabot for actions and pip"
git push

# ----------------------------------- 6. wait for CI, then protect the branch
say "Waiting for the first CI run"
sleep 10
gh run list --limit 3
echo
echo "Watch it with:  gh run watch"
echo
echo "Once 'all checks passed' has run at least once, require it:"
cat <<EOF

  gh api -X PUT repos/$GH_USER/$REPO/branches/main/protection \\
    --input - <<'JSON'
  {
    "required_status_checks": {
      "strict": true,
      "contexts": ["all checks passed"]
    },
    "enforce_admins": false,
    "required_pull_request_reviews": null,
    "restrictions": null,
    "allow_force_pushes": false,
    "allow_deletions": false
  }
  JSON

EOF

say "Done"
echo "Repository: https://github.com/$GH_USER/$REPO"
echo
echo "To cut the first release (runs every gate before publishing):"
echo "  git tag -a v0.1.0 -m 'debfed 0.1.0'"
echo "  git push origin v0.1.0"
echo "  gh run watch"
