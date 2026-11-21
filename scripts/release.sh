#!/bin/sh
# Cut a signed release:  scripts/release.sh v0.2.0
#
# Needs: a clean tree, cargo-zigbuild, gh, and JAWORD_RELEASE_KEY pointing at
# the SSH signing key (a public key file if the private half lives in an SSH
# agent such as 1Password, which then asks for approval on every signature).
#
# The signing key is the most sensitive thing in this project: whoever can
# sign a release can replace the vault's code. Keep it where only a human
# approval can use it.
set -eu
V=${1:?usage: release.sh vX.Y.Z}
printf '%s' "$V" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo "version must look like v0.2.0"; exit 2; }
KEY=${JAWORD_RELEASE_KEY:?set JAWORD_RELEASE_KEY to the release signing key}
REPO=${JAWORD_UPDATE_REPO:-toolingdev/jaword}
REMOTE=${JAWORD_RELEASE_REMOTE:-toolingdev}
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean"; exit 1; }

for f in crates/core/Cargo.toml crates/server/Cargo.toml crates/cli/Cargo.toml; do
  sed -i.bak -E "0,/^version = \"[0-9.]+\"/s//version = \"${V#v}\"/" "$f" 2>/dev/null \
    || perl -0pi -e "s/^version = \"[0-9.]+\"/version = \"${V#v}\"/m" "$f"
  rm -f "$f.bak"
done
cargo test -q
cargo zigbuild -q --release --target x86_64-unknown-linux-musl
cargo build -q --release

rm -rf dist && mkdir dist
cp target/x86_64-unknown-linux-musl/release/jawordd dist/jawordd-x86_64-linux-musl
cp target/x86_64-unknown-linux-musl/release/jaword dist/jaword-x86_64-linux-musl
cp target/release/jaword "dist/jaword-$(uname -m)-$(uname -s | tr A-Z a-z)"
for f in dist/*; do
  n=$(basename "$f")
  # Namespace binds the signature to this exact version and file name.
  ssh-keygen -Y sign -f "$KEY" -n "jaword-release-$V-$n" "$f"
done
(cd dist && shasum -a 256 $(ls | grep -v '\.sig$') > SHA256SUMS)

# UTC so the commit does not record the local timezone.
TZ=UTC git commit -qam "Release $V"
git tag "$V"
git push -q "$REMOTE" HEAD:main "$V"
gh release create "$V" dist/* --repo "$REPO" --title "$V" --notes "Signed release $V. The vault verifies the signature before installing."
echo "released $V"
