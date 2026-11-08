#!/bin/bash
# PostToolUse: keep Go files gofmt'ed right after every edit, so CI's
# gofmt check never fails.
path=$(jq -r '.tool_input.file_path // ""')
if [[ "$path" == *.go && -f "$path" ]]; then
  gofmt -w "$path" 2>&1 >/dev/null || {
    echo "gofmt 실패 ($path): 문법 오류를 확인하세요." >&2
    exit 2
  }
fi
exit 0
