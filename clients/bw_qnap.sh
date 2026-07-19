#!/bin/sh
# clients/bw_qnap.sh
# Shell wrapper for bw_minimal.py on QNAP QTS.
# Auto-detects Python 3 from Entware (/opt/bin/python) or system paths.
#
# Usage:
#   sh bw_qnap.sh get nas/ssh_pass
#   sh bw_qnap.sh set nas/ssh_pass mysecret

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BW_PY="$SCRIPT_DIR/bw_minimal.py"

# Locate Python 3 — Entware first, then system paths
PYTHON=''
for candidate in \
  /opt/bin/python3 \
  /opt/bin/python \
  /usr/local/bin/python3 \
  /usr/bin/python3 \
  python3
do
  if command -v "$candidate" >/dev/null 2>&1; then
    _ver=$("$candidate" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo 0)
    if [ "$_ver" = '3' ]; then
      PYTHON="$candidate"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  printf 'Error: Python 3 not found. Install via Entware: opkg install python3\n' >&2
  exit 1
fi

exec "$PYTHON" "$BW_PY" "$@"
