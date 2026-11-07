#!/bin/bash
# PreToolUse: blocks actions that are never wanted in this repo.
# Exit 2 = block; the stderr message is shown to Claude.
input=$(cat)
tool=$(jq -r '.tool_name // ""' <<<"$input")

case "$tool" in
  Edit|Write|MultiEdit|NotebookEdit)
    path=$(jq -r '.tool_input.file_path // ""' <<<"$input")
    if [[ "$path" == */frontend/wailsjs/* ]]; then
      echo "frontend/wailsjs/ 는 생성 파일입니다. Go 바인딩을 바꾼 뒤 '~/go/bin/wails generate module' 로 재생성하세요." >&2
      exit 2
    fi
    ;;
  Bash)
    cmd=$(jq -r '.tool_input.command // ""' <<<"$input")
    if grep -Eq 'git[[:space:]]+push([^|;&]*[[:space:]])(-f|--force)([[:space:]]|$|=)' <<<"$cmd"; then
      echo "force push는 차단되어 있습니다. 히스토리를 다시 써야 한다면 사용자에게 먼저 확인하세요." >&2
      exit 2
    fi
    if grep -Eq 'GIT_(AUTHOR|COMMITTER)_DATE|git[[:space:]]+commit[^|;&]*--date' <<<"$cmd"; then
      echo "커밋 날짜 조작은 이 레포에서 허용되지 않습니다 (CLAUDE.md 참고)." >&2
      exit 2
    fi
    ;;
esac
exit 0
