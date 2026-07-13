#!/usr/bin/env bash
# Idempotent `cargo publish` for one workspace member.
#
# Publishes the named package; if that exact version is already on crates.io
# (a re-run after a partial release, or a manual retry), it treats "already
# uploaded/exists" as success so the release job is safe to re-run.
#
# Usage: publish-crate.sh <package-name>
set -euo pipefail

pkg="${1:?usage: publish-crate.sh <package-name>}"

if out="$(cargo publish --locked -p "$pkg" 2>&1)"; then
  echo "$out"
  echo ">> published $pkg"
else
  echo "$out"
  if echo "$out" | grep -qiE "already (uploaded|exists)"; then
    echo ">> $pkg is already on crates.io at this version, skipping (idempotent)"
  else
    exit 1
  fi
fi
