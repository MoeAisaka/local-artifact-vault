#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
python3 scripts/secret_scan.py --tracked
PYTHONPATH=src python3 -m unittest discover -s tests -v
if command -v gitleaks >/dev/null 2>&1; then
  if [ "${PREFLIGHT_MODE:-commit}" = commit ]; then gitleaks git --staged --redact --no-banner .; else gitleaks git --redact --no-banner .; fi
fi
