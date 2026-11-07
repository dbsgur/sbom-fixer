#!/bin/bash
# Stop: before Claude finishes a turn, run the fast checks for whatever
# changed. Exit 2 keeps Claude working with the failure output as feedback.
input=$(cat)
# Already continuing because of this hook → don't loop forever.
[[ "$(jq -r '.stop_hook_active // false' <<<"$input")" == "true" ]] && exit 0

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}" || exit 0
changed=$(git status --porcelain --untracked-files=all 2>/dev/null)
[[ -z "$changed" ]] && exit 0

fail() {
  echo "검증 실패: $1" >&2
  echo "$2" | tail -40 >&2
  exit 2
}

if grep -Eq '\.go$|(^|/)go\.(mod|sum)$' <<<"$changed"; then
  out=$(go vet ./internal/... 2>&1) || fail "go vet" "$out"
  out=$(go test ./internal/... 2>&1) || fail "go test" "$out"
fi

if grep -Eq 'frontend/(src/|package\.json|vite\.config)' <<<"$changed"; then
  out=$(cd frontend && npx tsc --noEmit 2>&1) || fail "tsc" "$out"
  out=$(cd frontend && npx vitest run 2>&1) || fail "vitest" "$out"
fi
exit 0
