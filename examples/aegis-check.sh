#!/usr/bin/env bash
# Aegis agent gate helper — print decision and exit 0 only on allow.
set -euo pipefail
URL="${1:?usage: aegis-check.sh <url>}"
BASE="${AEGIS_BASE:-http://127.0.0.1:7832/api/v1}"
RESP=$(curl -sS -X POST "$BASE/check" \
  -H 'content-type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"url":sys.argv[1],"context":sys.argv[2] if len(sys.argv)>2 else None}))' "$URL" "${2:-}")")
DECISION=$(printf '%s' "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["decision"])')
echo "$RESP"
if [ "$DECISION" = "allow" ]; then
  exit 0
fi
exit 1
