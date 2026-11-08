import {Fragment, useMemo, useState} from 'react'
import {openURL} from '../api'
import {Finding, SEVERITIES, SEVERITY_LABEL, Severity} from '../types'
import {ecosystemsOf, filterFindings, findingKey, jsPackageManager} from '../lib/findings'
import {toggled} from '../lib/selection'
import SeverityBadge from './SeverityBadge'

interface Props {
  findings: Finding[]
  selected: Set<string>
  onToggle: (f: Finding) => void
  onSetMany: (fs: Finding[], on: boolean) => void
}

export default function FindingsTable({findings, selected, onToggle, onSetMany}: Props) {
  const [query, setQuery] = useState('')
  const [sev, setSev] = useState<Severity | 'ALL'>('ALL')
  const [eco, setEco] = useState('ALL')
  const [fixableOnly, setFixableOnly] = useState(false)
  const [open, setOpen] = useState<Set<string>>(new Set())

  const ecosystems = useMemo(() => ecosystemsOf(findings), [findings])
  const rows = useMemo(
    () => filterFindings(findings, {query, severity: sev, ecosystem: eco, fixableOnly}),
    [findings, query, sev, eco, fixableOnly],
  )

  const fixableRows = rows.filter(f => f.fixable)
  const allChecked = fixableRows.length > 0 && fixableRows.every(f => selected.has(findingKey(f)))

  if (findings.length === 0) {
    return (
      <div className="all-clear">
        <div className="all-clear-icon">✓</div>
        <div>알려진 취약점이 있는 패키지가 없습니다.</div>
      </div>
    )
  }

  const toggleOpen = (k: string) => setOpen(prev => toggled(prev, k))

  return (
    <div className="panel">
      <div className="filters">
        <input placeholder="패키지명 / CVE / GHSA 검색" value={query} onChange={e => setQuery(e.target.value)} />
        <select value={sev} onChange={e => setSev(e.target.value as Severity | 'ALL')}>
          <option value="ALL">모든 심각도</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
        </select>
        <select value={eco} onChange={e => setEco(e.target.value)}>
          <option value="ALL">모든 생태계</option>
          {ecosystems.map(e => <option key={e} value={e}>{e}</option>)}
        </select>
        <label className="check">
          <input type="checkbox" checked={fixableOnly} onChange={e => setFixableOnly(e.target.checked)} />
          수정 가능한 항목만
        </label>
        <span className="muted right">{rows.length}개 표시</span>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th className="col-check">
                <input
                  type="checkbox"
                  checked={allChecked}
                  disabled={fixableRows.length === 0}
                  onChange={e => onSetMany(fixableRows, e.target.checked)}
                  title="수정 가능한 항목 전체 선택"
                />
              </th>
              <th>심각도</th>
              <th>패키지</th>
              <th>현재 버전</th>
              <th>수정 버전</th>
              <th>취약점</th>
              <th>위치</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(f => {
              const k = findingKey(f)
              const isOpen = open.has(k)
              const c = f.component
              return (
                <Fragment key={k}>
                  <tr className={selected.has(k) ? 'row selected' : 'row'} onClick={() => toggleOpen(k)}>
                    <td className="col-check" onClick={e => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selected.has(k)}
                        disabled={!f.fixable}
                        title={f.fixable ? '' : '공개된 수정 버전이 없습니다'}
                        onChange={() => onToggle(f)}
                      />
                    </td>
                    <td><SeverityBadge s={f.severity} /></td>
                    <td>
                      <div className="pkg">
                        <span className="caret">{isOpen ? '▾' : '▸'}</span>
                        <span className="pkg-name">{c.name}</span>
                      </div>
                      <div className="pkg-tags">
                        <span className="chip">{c.ecosystem}</span>
                        <span className={c.direct ? 'chip direct' : 'chip'}>{c.direct ? '직접' : '간접'}</span>
                        {c.dev && <span className="chip">dev</span>}
                      </div>
                    </td>
                    <td className="mono">{c.version}</td>
                    <td className="mono">
                      {f.fixable ? (
                        <>
                          <span className="fix-version">{f.fixVersion}</span>
                          {f.majorBump && <span className="tag warn" title="메이저 버전이 바뀌어 호환성 문제가 생길 수 있습니다">메이저 변경</span>}
                          {!f.fullyFixed && <span className="tag" title="일부 취약점은 아직 수정 버전이 없습니다">일부만 해결</span>}
                          {f.targetVulnerable && <span className="tag warn" title="수정 버전에도 아직 해결되지 않은 취약점이 있습니다">미해결 잔존</span>}
                        </>
                      ) : (
                        <span className="muted">수정 버전 없음</span>
                      )}
                    </td>
                    <td>{f.vulns.length}건</td>
                    <td className="mono muted small">{c.manifest}</td>
                  </tr>
                  {isOpen && (
                    <tr className="detail">
                      <td />
                      <td colSpan={6}>
                        <ul className="vulns">
                          {f.vulns.map(v => (
                            <li key={v.id}>
                              <SeverityBadge s={v.severity} />
                              <button className="link mono" onClick={() => openURL(v.url)}>{v.id}</button>
                              {(v.aliases ?? []).filter(a => a.startsWith('CVE-')).map(a => (
                                <span key={a} className="chip mono">{a}</span>
                              ))}
                              <span className="vuln-summary">{v.summary || '(설명 없음)'}</span>
                              <span className="muted small">
                                {v.fixedVersion ? `→ ${v.fixedVersion}에서 수정` : '수정 버전 없음'}
                              </span>
                            </li>
                          ))}
                        </ul>
                        {!c.direct && c.ecosystem === 'npm' && (
                          <div className="hint">
                            간접 의존성입니다. 수정 시 package.json의 <code>{jsPackageManager(c.manifest).override}</code>로 버전을 강제합니다.
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
