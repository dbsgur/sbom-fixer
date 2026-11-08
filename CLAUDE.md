# SBOM Fixer

Wails v2 데스크톱 앱. 레포 폴더 → SBOM 생성 → OSV.dev 취약점 조회 → 선택 패키지 자동 수정.

## 명령어

- 테스트: `make test` (Go `-race` + vitest). 커밋 전 반드시 통과
- 실제 네트워크/npm/go까지 도는 e2e: `make test-e2e` (느림, 수동 실행)
- 앱 빌드: `make build` → `build/bin/sbomapp.app`
- Wails CLI가 PATH에 없을 수 있음: `~/go/bin/wails`
- UI를 눈으로 확인할 때: `verify-ui` 스킬 사용

## 환경 제약

- Node 버전은 `.nvmrc`(24 LTS). 프론트엔드 명령 전에 `source ~/.nvm/nvm.sh && nvm use` (셸 기본 node는 18일 수 있음)
- 프론트엔드는 Vite 5 / vitest 2 사용 중. 메이저 업그레이드는 별도 PR로
- `frontend/wailsjs/`는 생성 파일. 직접 수정 금지 → Go 바인딩 변경 후 `~/go/bin/wails generate module`
- 앱 실행 시 Node는 불필요 (frontend/dist가 바이너리에 임베드됨)

## 아키텍처 규칙

- Wails 의존은 `app.go`와 `frontend/src/api.ts`에만. 비즈니스 로직은 `internal/service`
- `internal/*` 패키지는 인터페이스로 의존 (`service.Scanner/Checker/Fixer/GitInspector`, `vuln.AdvisoryDB`, `fixer.Fixer/Runner`)
- 테스트는 가짜 구현으로 작성. 유닛 테스트에서 네트워크·npm·go 실행 금지 (e2e는 `//go:build e2e`)
- 프론트엔드 순수 로직은 `src/lib/`에 두고 vitest로 테스트. 컴포넌트는 `src/components/`
- 새 생태계 지원 → `add-ecosystem` 스킬의 체크리스트를 따를 것

## 커밋/PR

- 한국어 Conventional Commits: `feat(sbom): ...`, `fix(fixer): ...`, `test(vuln): ...`, `refactor`, `docs`, `ci`, `chore`
- 기능 하나 = 브랜치 하나 = PR 하나. 리팩터링·테스트·버그 수정은 커밋을 분리
- `main`에 직접 푸시하지 않음. CI(`.github/workflows/ci.yml`) 통과 후 머지
- 커밋 날짜(`GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE`, `--date`)를 조작하지 않음
