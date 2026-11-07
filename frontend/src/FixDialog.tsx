import {Finding} from './api'
import {SeverityBadge} from './FindingsTable'

function planText(f: Finding): string {
  const c = f.component
  switch (c.ecosystem) {
    case 'npm':
      return c.direct
        ? 'package.json 의존성 버전 변경 → npm install --package-lock-only'
        : 'package.json overrides 추가 → npm install --package-lock-only'
    case 'Go':
      return `go get ${c.name}@${f.fixVersion} → go mod tidy`
    case 'PyPI':
      return `${c.manifest}의 고정 버전 교체`
  }
  return ''
}

export default function FixDialog({findings, onCancel, onConfirm}: {
  findings: Finding[]
  onCancel: () => void
  onConfirm: () => void
}) {
  const majors = findings.filter(f => f.majorBump)
  const manifests = Array.from(new Set(findings.map(f => f.component.manifest)))
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>{findings.length}개 패키지를 수정합니다</h2>
        <p className="muted">
          대상 매니페스트: {manifests.join(', ')}. 패키지 매니저가 실패하면 해당 파일은 원래대로 복구됩니다.
          수정이 끝나면 자동으로 다시 분석합니다.
        </p>
        {majors.length > 0 && (
          <div className="banner warn">
            메이저 버전이 바뀌는 패키지 {majors.length}개가 포함되어 있습니다
            ({majors.map(f => f.component.name).join(', ')}). API 호환성을 확인하고 테스트를 실행하세요.
          </div>
        )}
        <div className="table-wrap modal-list">
          <table className="table">
            <thead>
              <tr><th>심각도</th><th>패키지</th><th>변경</th><th>작업</th></tr>
            </thead>
            <tbody>
              {findings.map(f => (
                <tr key={`${f.component.manifest}|${f.component.name}@${f.component.version}`}>
                  <td><SeverityBadge s={f.severity} /></td>
                  <td className="pkg-name">{f.component.name}</td>
                  <td className="mono nowrap">{f.component.version} → <b>{f.fixVersion}</b></td>
                  <td className="muted small">{planText(f)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="modal-actions">
          <button className="ghost" onClick={onCancel}>취소</button>
          <button className="primary" onClick={onConfirm} autoFocus>수정 실행</button>
        </div>
      </div>
    </div>
  )
}
