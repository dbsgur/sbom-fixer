import {FixReport} from '../types'

export default function ResultDialog({report, onClose}: {report: FixReport; onClose: () => void}) {
  const results = report.fix.results ?? []
  const ok = results.filter(r => r.success).length
  const failed = results.length - ok
  const remaining = report.rescan?.findings.length
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>수정 결과</h2>
        <div className="result-summary">
          <span className="ok">성공 {ok}</span>
          {failed > 0 && <span className="fail">실패 {failed}</span>}
          {remaining !== undefined && <span className="muted">재분석 결과 남은 취약 패키지 {remaining}개</span>}
        </div>

        <ul className="results">
          {results.map((r, i) => (
            <li key={i} className={r.success ? 'ok-item' : 'fail-item'}>
              <span className="result-icon">{r.success ? '✓' : '✕'}</span>
              <div>
                <div>
                  <b>{r.request.name}</b>{' '}
                  <span className="mono muted">{r.request.currentVersion} → {r.request.targetVersion}</span>
                </div>
                <div className="small muted">{r.message}</div>
              </div>
            </li>
          ))}
        </ul>

        {(report.fix.changedFiles?.length ?? 0) > 0 && (
          <div className="section">
            <h3>변경된 파일</h3>
            <ul className="mono small">
              {report.fix.changedFiles!.map(f => <li key={f}>{f}</li>)}
            </ul>
            <p className="muted small">git diff로 변경 내용을 검토한 뒤 테스트/빌드를 실행하고 커밋하세요.</p>
          </div>
        )}

        {(report.fix.commands?.length ?? 0) > 0 && (
          <details className="section">
            <summary>실행한 명령 로그 ({report.fix.commands!.length})</summary>
            {report.fix.commands!.map((c, i) => (
              <div key={i} className="cmd">
                <div className={c.success ? 'ok mono small' : 'fail mono small'}>
                  {c.success ? '✓' : '✕'} [{c.dir || '.'}] $ {c.command}
                </div>
                {c.output && <pre>{c.output}</pre>}
              </div>
            ))}
          </details>
        )}

        <div className="modal-actions">
          <button className="primary" onClick={onClose}>확인</button>
        </div>
      </div>
    </div>
  )
}
