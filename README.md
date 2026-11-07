# SBOM Fixer

[![CI](https://github.com/dbsgur/sbom-fixer/actions/workflows/ci.yml/badge.svg)](https://github.com/dbsgur/sbom-fixer/actions/workflows/ci.yml)

레포지토리(폴더)를 선택하면 **SBOM을 생성하고, 알려진 취약점이 있는 패키지를 찾아, 선택한 패키지를 안전한 버전으로 자동 수정**하는 데스크톱 앱입니다. [Wails v2](https://wails.io) (Go + React/TypeScript)로 만들었습니다.

## 기능

- **SBOM 생성**: `package-lock.json`(npm, v1~v3), `go.mod`, `requirements*.txt`를 재귀적으로 탐색합니다 (`node_modules`, `vendor`, 숨김 폴더 제외)
- **취약점 분석**: [OSV.dev](https://osv.dev) API로 조회합니다. 심각도(GHSA 등급, 없으면 CVSS v3로 계산), 직접/간접 의존성, 권장 수정 버전을 보여 줍니다
  - 권장 수정 버전 자체가 다른 취약점에 걸려 있으면 다시 조회해서 버전을 올립니다
  - 메이저 버전이 바뀌거나 일부 취약점만 해결되는 경우는 경고로 표시합니다
- **자동 수정**
  | 생태계 | 직접 의존성 | 간접 의존성 |
  |---|---|---|
  | npm | `package.json` 버전 변경 (`^`/`~` 등 범위 형식 유지) | `overrides` 추가 |
  | Go | `go get mod@ver` → `go mod tidy` | 동일 |
  | Python | `requirements.txt`의 고정 버전 교체 | – |

  패키지 매니저가 실패하면 파일을 원래대로 복구합니다. 수정이 끝나면 결과를 검증하고 자동으로 다시 분석합니다.
- **CycloneDX 1.5 JSON 내보내기**
- 폴더를 창으로 드래그 앤 드롭하거나 `sbomapp <폴더>` 인자로 실행할 수 있습니다

## 아키텍처

```
main.go / app.go         Wails 어댑터 (다이얼로그, 진행 이벤트) — 비즈니스 로직 없음
internal/
  service/   분석 → 취약점 조회 → 수정 → 재분석 오케스트레이션 (인터페이스에만 의존)
  sbom/      Scanner + 생태계별 Parser (npm / Go / PyPI), CycloneDX
  vuln/      Checker(분석 로직) ← AdvisoryDB 인터페이스 → OSVClient(HTTP)
  fixer/     Service + 생태계별 Fixer, Runner(외부 명령), Workspace(백업/로그)
  gitutil/   git 상태 조회
  shellenv/  Finder로 실행했을 때 npm/go를 찾을 수 있도록 PATH 보정
frontend/src/
  api.ts     Wails 바인딩 브리지 (Wails에 의존하는 유일한 파일)
  types.ts   Go JSON과 맞춘 도메인 타입
  lib/       순수 로직 (필터, 선택, 수정 요청 변환)
  components/
```

- **확장**: 새 생태계(예: Cargo)를 지원하려면 `sbom.Parser`와 `fixer.Fixer`를 구현해서 등록하면 됩니다
- **테스트 용이성**: `service`, `vuln.Checker`, `fixer`는 인터페이스로 의존성을 주입받습니다. 그래서 네트워크나 npm/go 없이 가짜 구현으로 테스트할 수 있습니다

## 개발

필요한 것: Go 1.22+, Node 18+, Wails CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`)

```bash
make dev      # 개발 모드 (핫 리로드)
make build    # build/bin/sbomapp.app
make test     # Go(-race) + 프론트엔드(vitest) 유닛 테스트
make cover    # 커버리지
```

수정 기능을 쓰려면 대상 프로젝트의 패키지 매니저(`npm`, `go`)가 설치되어 있어야 합니다.
