---
name: verify-ui
description: SBOM Fixer 프론트엔드나 Wails 바인딩을 바꾼 뒤 실제 화면과 동작(분석 결과 표시, 선택, 수정 다이얼로그, 결과)을 브라우저로 확인할 때 사용. wails dev + Chrome 연동으로 스크린샷을 찍어 검증.
---

# UI 직접 확인

macOS 앱 창은 화면 녹화 권한이 없으면 캡처되지 않는다. 대신 `wails dev`가 띄우는 **http://localhost:34115**를 Chrome으로 연다. 이 주소에서도 Go 바인딩(Scan/ApplyFixes 등)이 그대로 동작한다.

## 절차

1. 샘플 레포 준비 (임시 디렉터리에 복사하므로 수정을 실행해도 안전함)
   ```bash
   FIXTURE=$(.claude/skills/verify-ui/prepare-fixture.sh)
   ```
2. dev 서버 실행 (Bash `run_in_background`). `-appargs`로 넘긴 폴더는 앱 시작 시 자동 분석됨
   ```bash
   source ~/.nvm/nvm.sh && nvm use >/dev/null
   ~/go/bin/wails dev -appargs "$FIXTURE" -noreload > /tmp/wailsdev.log 2>&1
   ```
   준비 확인: `/tmp/wailsdev.log`에 `Using DevServer URL: http://localhost:34115`가 뜨고 `curl -s localhost:34115`가 HTML을 반환할 때까지 대기
3. `claude-in-chrome` 스킬로 새 탭에서 `http://localhost:34115`를 열고 약 8초(분석 시간) 기다린 뒤 스크린샷
4. 바뀐 부분에 맞춰 확인
   - 요약 카드: 컴포넌트 6 / 취약 패키지 5 / 치명 1, 높음 4
   - 조치 필요 표: minimist(간접), golang.org/x/text, jinja2(메이저 변경), lodash, requests
   - 전체 선택 → "선택 항목 수정" → 확인 다이얼로그 → "수정 실행" → 결과 "성공 5, 남은 취약 패키지 0개"
   - 콘솔 오류: `read_console_messages`에 pattern `error|Error`
5. 정리: 탭 닫기, `pkill -f "wails dev"; pkill -f vite`

## 주의
- 네이티브 다이얼로그(폴더 선택, SBOM 저장)는 브라우저에서 조작할 수 없다. 폴더는 `-appargs`로 지정한다
- 브라우저의 `alert/confirm`을 띄우는 동작은 피한다 (앱은 쓰지 않음)
- 사용자에게 보여 줄 스크린샷은 `save_to_disk: true`로 저장하고 경로를 알려 준다
