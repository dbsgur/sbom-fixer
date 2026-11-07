import {useMemo, useState} from 'react'
import {Component, Finding} from './api'
import {SeverityBadge} from './FindingsTable'

const PAGE = 300

export default function ComponentsTable({components, findings}: {components: Component[]; findings: Finding[]}) {
  const [query, setQuery] = useState('')
  const [limit, setLimit] = useState(PAGE)

  const vulnByKey = useMemo(() => {
    const m = new Map<string, Finding>()
    findings.forEach(f => m.set(`${f.component.manifest}|${f.component.name}@${f.component.version}`, f))
    return m
  }, [findings])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return q ? components.filter(c => c.name.toLowerCase().includes(q) || c.purl.toLowerCase().includes(q)) : components
  }, [components, query])

  return (
    <div className="panel">
      <div className="filters">
        <input placeholder="컴포넌트 검색" value={query} onChange={e => { setQuery(e.target.value); setLimit(PAGE) }} />
        <span className="muted right">{rows.length}개</span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>이름</th>
              <th>버전</th>
              <th>생태계</th>
              <th>유형</th>
              <th>PURL</th>
              <th>위치</th>
              <th>상태</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, limit).map(c => {
              const f = vulnByKey.get(`${c.manifest}|${c.name}@${c.version}`)
              return (
                <tr key={`${c.ecosystem}|${c.manifest}|${c.name}@${c.version}`} className="row">
                  <td className="pkg-name">{c.name}</td>
                  <td className="mono">{c.version}</td>
                  <td><span className="chip">{c.ecosystem}</span></td>
                  <td>{c.direct ? '직접' : '간접'}{c.dev ? ' · dev' : ''}</td>
                  <td className="mono muted small ellipsis" title={c.purl}>{c.purl}</td>
                  <td className="mono muted small">{c.manifest}</td>
                  <td>{f ? <SeverityBadge s={f.severity} /> : <span className="ok">안전</span>}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {rows.length > limit && (
          <div className="more">
            <button className="ghost" onClick={() => setLimit(l => l + PAGE)}>더 보기 ({rows.length - limit}개 남음)</button>
          </div>
        )}
      </div>
    </div>
  )
}
