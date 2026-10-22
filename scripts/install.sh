#!/usr/bin/env bash
# Builds toolbox in release mode and installs it to $TOOLBOX_INSTALL_DIR (default ~/.cargo/bin),
# with `tb` as a symlink to the same binary.
# On macOS it signs the binary with the hardened runtime, so DYLD_* injection and
# debuggers can't get inside the process that is allowed to read the vault.
set -euo pipefail

cd "$(dirname "$0")/.."
dest="${TOOLBOX_INSTALL_DIR:-$HOME/.cargo/bin}"

cargo build --release
mkdir -p "$dest"
# Remove first: overwriting a signed binary in place can get it killed by macOS.
rm -f "$dest/toolbox" "$dest/tb"
cp target/release/toolbox "$dest/toolbox"
# A symlink, not a copy: the keychain sees one signed binary, so it only asks once.
ln -s toolbox "$dest/tb"

if [[ "$(uname)" == "Darwin" ]]; then
  codesign --force --sign - --options runtime "$dest/toolbox"
  if DYLD_PRINT_LIBRARIES=1 "$dest/tb" --version 2>&1 | grep -q '^dyld'; then
    echo "error: hardened runtime is not active on $dest/toolbox" >&2
    exit 1
  fi
fi

echo "installed $dest/toolbox and $dest/tb ($("$dest/tb" --version))"
