#!/usr/bin/env bash
# Install the version-controlled git hooks into .git/hooks/.
#
# Uses symlinks so that future updates to scripts/hooks/* propagate automatically.
# Re-run this script whenever a new hook is added.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SRC_DIR="$REPO_ROOT/scripts/hooks"
DST_DIR="$REPO_ROOT/.git/hooks"

if [ ! -d "$DST_DIR" ]; then
  echo "install.sh: $DST_DIR does not exist — is this a git repo?" >&2
  exit 1
fi

for hook_src in "$SRC_DIR"/*; do
  name="$(basename "$hook_src")"
  # Skip this installer itself
  [ "$name" = "install.sh" ] && continue

  dst="$DST_DIR/$name"
  chmod +x "$hook_src"
  ln -sf "$hook_src" "$dst"
  echo "installed: $dst -> $hook_src"
done

echo "done. Skip a hook once with: git commit --no-verify"
