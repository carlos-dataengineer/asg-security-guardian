#!/usr/bin/env sh
# ASG Security Guardian — one-command installer (Linux / macOS / Git Bash).
#
#   From a clone:   ./install.sh [--target claude|codex|all] [--lang en] [--add-to-path]
#   One command:    curl -fsSL https://raw.githubusercontent.com/carlos-dataengineer/asg-security-guardian/main/install.sh | sh
#
# Piped mode clones the repository (git required) into ~/.asg-security-guardian/src and runs install.py.
# Read this file before piping it to a shell — that is exactly the habit ASG asks you to keep.
set -eu

REPO_URL="${ASG_REPO:-https://github.com/carlos-dataengineer/asg-security-guardian.git}"
REF="${ASG_REF:-main}"
SRC="${ASG_STATE:-$HOME/.asg-security-guardian}/src"

PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
[ -n "$PY" ] || { echo "ASG: Python 3.10+ is required (https://www.python.org/downloads/)." >&2; exit 1; }

HERE=""
case "$0" in
  */install.sh|install.sh) HERE="$(cd "$(dirname "$0")" && pwd)" ;;
esac

if [ -n "$HERE" ] && [ -f "$HERE/install.py" ]; then
  exec "$PY" "$HERE/install.py" "$@"
fi

command -v git >/dev/null 2>&1 || { echo "ASG: git is required for the one-command install." >&2; exit 1; }
if [ -d "$SRC/.git" ]; then
  echo "ASG: updating $SRC ($REF)"
  git -C "$SRC" fetch --depth 1 origin "$REF" && git -C "$SRC" checkout -q FETCH_HEAD
else
  echo "ASG: downloading $REPO_URL ($REF) -> $SRC"
  mkdir -p "$(dirname "$SRC")"
  git clone -q --depth 1 --branch "$REF" "$REPO_URL" "$SRC"
fi
exec "$PY" "$SRC/install.py" "$@"
