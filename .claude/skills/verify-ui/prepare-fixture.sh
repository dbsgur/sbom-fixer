#!/bin/bash
# Copies the vulnerable sample repo to a fresh temp dir (stripping the
# ".fixture" suffix) and prints its path. Safe to run fixes against.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
dst="$(mktemp -d)/repo"
mkdir -p "$dst"
cp -R "$root/internal/service/testdata/vulnerable/." "$dst"
find "$dst" -name '*.fixture' | while read -r f; do mv "$f" "${f%.fixture}"; done
echo "$dst"
