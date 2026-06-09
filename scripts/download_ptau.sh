#!/usr/bin/env bash
# Download the Powers of Tau file needed for the Groth16 trusted setup.
#
# The .ptau is a large binary (~75 MB for 2^16) and is intentionally NOT
# committed (see .gitignore). Run this once before `npm run setup`.
#
# Usage:
#   bash scripts/download_ptau.sh [POWER]   # POWER defaults to 16
set -euo pipefail

POWER="${1:-16}"
OUT="pot${POWER}_final.ptau"

# Mirrors of the Hermez Phase-1 ceremony output. Tried in order.
URLS=(
  "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_${POWER}.ptau"
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${POWER}.ptau"
)

cd "$(dirname "$0")/.."

if [ -f "$OUT" ]; then
  echo "$OUT already present; nothing to do."
  exit 0
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "$OUT" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$OUT" "$1"
  else
    echo "Need curl or wget to download the ptau." >&2
    return 2
  fi
}

for url in "${URLS[@]}"; do
  echo "Trying $url"
  if fetch "$url"; then
    echo "Done. $(du -h "$OUT" | cut -f1) $OUT"
    echo "Note: 2^16 (~65k constraints) fits V1 (~50k). If V2 exceeds it,"
    echo "re-run with a larger power, e.g.: bash scripts/download_ptau.sh 17"
    exit 0
  fi
  rm -f "$OUT"
done

echo "All mirrors failed for power ${POWER}." >&2
exit 1
