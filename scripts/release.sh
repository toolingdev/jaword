#!/bin/sh
# Cut a release:  scripts/release.sh v0.2.0
#
# Bumps the version, commits, tags and pushes. GitHub Actions
# (.github/workflows/release.yml) then builds, signs and publishes it.
# Binaries are never built locally for a release: local builds embed
# paths from the build machine.
#
# The signing key lives only in the JAWORD_RELEASE_KEY repository secret.
# Whoever can push a tag to the repository can ship code to every vault
# that trusts that key, so protect the GitHub account accordingly.
set -eu
V=${1:?usage: release.sh vX.Y.Z}
printf '%s' "$V" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo "version must look like v0.2.0"; exit 2; }
REMOTE=${JAWORD_RELEASE_REMOTE:-toolingdev}
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean"; exit 1; }

for f in crates/core/Cargo.toml crates/server/Cargo.toml crates/cli/Cargo.toml; do
  perl -0pi -e "s/^version = \"[0-9.]+\"/version = \"${V#v}\"/m" "$f"
done
cargo test -q --workspace

# UTC so the commit does not record the local timezone.
TZ=UTC git commit -qam "Release $V"
git tag "$V"
git push -q "$REMOTE" HEAD:main "$V"
echo "pushed $V; the release workflow publishes it"
