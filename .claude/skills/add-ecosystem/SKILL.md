---
name: add-ecosystem
description: SBOM Fixer에 새 패키지 생태계나 lock 파일 형식(yarn.lock, pnpm-lock.yaml, poetry.lock, uv.lock, Cargo.lock 등)의 분석/수정 지원을 추가할 때 사용. 파서, 수정기, 테스트, 픽스처, 문서를 빠짐없이 갱신하는 체크리스트.
---

# 새 생태계 / lock 형식 추가

브랜치 이름은 `feat/<ecosystem>-support`. 아래 단계마다 커밋을 나눈다.

## 0. 사전 확인
- OSV 생태계 이름 확인: https://ossf.github.io/osv-schema/#affectedpackage-field (예: `crates.io`, `Maven`, `RubyGems`). 기존 생태계의 새 lock 형식(yarn/pnpm → `npm`)이면 상수를 추가하지 않는다
- 버전 비교가 `vuln.CompareVersions`로 충분한지 확인. 부족하면 `internal/vuln/version_test.go`에 케이스를 먼저 추가한다

## 1. 파서 — `feat(sbom): <형식> 파서 추가`
- `internal/sbom/<eco>.go`에 `sbom.Parser`를 구현한다 (`Match`, `Label`, `Parse`). 컴포넌트 수집은 `newCollector`를 사용
- 직접/간접(`Direct`)과 dev 여부를 가능한 한 정확히 채운다
- 새 생태계면 `types.go`에 상수와 `makePURL` 분기(purl 스펙의 type)를 추가한다
- `DefaultParsers()`에 등록한다
- `internal/sbom/sbom_test.go`에 테이블 테스트를 추가한다: 정상, 깨진 파일, 직접/간접, 중복 제거

## 2. 수정기 — `feat(fixer): <형식> 자동 수정`
- `internal/fixer/<eco>.go`에 `fixer.Fixer`를 구현한다. 외부 명령은 반드시 `ws.Run`, 백업은 `ws.TakeBackup`, 실패하면 `Backup.Restore()`
- 수정한 뒤 해당 파서로 lock을 다시 읽어 실제로 반영됐는지 검증한다 (`NpmFixer` 참고)
- 파일 편집 로직은 I/O 없는 순수 함수로 분리한다 (`npmspec.go` 참고)
- `DefaultService()`에 등록한다
- 같은 생태계의 다른 lock 형식(yarn vs npm)은 매니페스트 파일 이름으로 분기한다. 매니페스트 → 수정기 매핑은 `Request.Manifest`로 결정된다
- `service_test.go` 스타일로 `fakeRunner` 테스트를 작성한다: 성공, 명령 실패 시 원복, 반영 안 됨 감지

## 3. UI — 필요한 경우만
- `frontend/src/lib/findings.ts`의 `fixPlan()`에 설명을 추가하고 `findings.test.ts`도 갱신한다

## 4. e2e 픽스처 — `test(e2e): <형식> 픽스처 추가`
- `internal/service/testdata/vulnerable/`에 알려진 취약 버전을 고정한 샘플을 추가한다
- **파일 이름 끝에 `.fixture`를 붙인다** (예: `yarn.lock.fixture`). GitHub Dependabot이 테스트 데이터를 실제 의존성으로 오인하지 않게 하기 위해서다. `e2e_test.go`가 복사할 때 접미사를 제거한다
- `e2e_test.go`의 기대 목록에 패키지를 추가하고 `make test-e2e`로 확인한다

## 5. 문서 — `docs: <형식> 지원 문서화`
- README의 기능 목록과 자동 수정 표, `Scan` 경고 문구(지원 파일 목록, `internal/service/service.go`)를 갱신한다

## 완료 조건
- `make test` 통과 (Stop hook이 자동 실행), `make test-e2e` 통과
- PR 본문에 지원 범위와 제한 사항(예: workspace 미지원)을 적는다
