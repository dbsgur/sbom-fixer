import {useEffect, useMemo, useRef, useState} from 'react'
import './App.css'
import {applyFixes, exportFormats, exportReport, initialPath, onFolderDrop, onProgress, openInFinder, scan, selectFolder} from './api'
import {ExportFormat, Finding, FixReport, ScanReport, SEVERITIES, SEVERITY_LABEL} from './types'
import {countVulns, findingKey, toFixRequest} from './lib/findings'
import {toggled, withAll} from './lib/selection'
import FindingsTable from './components/FindingsTable'
import ComponentsTable from './components/ComponentsTable'
import FixDialog from './components/FixDialog'
import ResultDialog from './components/ResultDialog'

type Tab = 'findings' | 'components'

export default function App() {
  const [root, setRoot] = useState('')
  const [report, setReport] = useState<ScanReport | null>(null)
  const [busy, setBusy] = useState<'' | 'scan' | 'fix'>('')
  const [progress, setProgress] = useState('')
  const [error, setError] = useState('')
  const [toast, setToast] = useState('')
  const [tab, setTab] = useState<Tab>('findings')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [confirming, setConfirming] = useState(false)
  const [fixReport, setFixReport] = useState<FixReport | null>(null)

  useEffect(() => onProgress(setProgress), [])

  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(''), 3500)
    return () => clearTimeout(t)
  }, [toast])

  const runScan = async (path: string) => {
    setBusy('scan')
    setError('')
    setProgress('분석 준비 중...')
    try {
      const r = await scan(path)
      setReport(r)
      setSelected(new Set())
      setTab('findings')
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy('')
    }
  }

  const openFolder = async (p: string) => {
    setRoot(p)
    setReport(null)
    await runScan(p)
  }

  const pickFolder = async () => {
    try {
      const p = await selectFolder()
      if (p) await openFolder(p)
    } catch (e) {
      setError(String(e))
    }
  }

  // Folder given on the command line, and drag & drop of a folder.
  const busyRef = useRef(busy)
  busyRef.current = busy
  const startedRef = useRef(false)
  useEffect(() => {
    if (!startedRef.current) {
      startedRef.current = true // StrictMode runs effects twice in dev
      initialPath().then(p => {
        if (p) openFolder(p)
      })
    }
    return onFolderDrop(dir => {
      if (!busyRef.current) openFolder(dir)
    })
  }, [])

  const findings = report?.findings ?? []
  const selectedFindings = useMemo(
    () => findings.filter(f => selected.has(findingKey(f))),
    [findings, selected],
  )

  const runFix = async () => {
    if (!report) return
    const reqs = selectedFindings.map(toFixRequest)
    setConfirming(false)
    setBusy('fix')
    setError('')
    setProgress('수정 준비 중...')
    try {
      const fr = await applyFixes(report.root, reqs)
      setFixReport(fr)
      if (fr.rescan) {
        setReport(fr.rescan)
      }
      setSelected(new Set())
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy('')
    }
  }

  const [formats, setFormats] = useState<ExportFormat[]>([])
  useEffect(() => {
    exportFormats().then(setFormats).catch(e => setError(String(e)))
  }, [])

  const doExport = async (f: ExportFormat) => {
    try {
      const p = await exportReport(f.id)
      if (p) setToast(`${f.label} 저장 완료: ${p}`)
    } catch (e) {
      setError(String(e))
    }
  }

  const toggle = (f: Finding) => setSelected(prev => toggled(prev, findingKey(f)))
  const setMany = (fs: Finding[], on: boolean) => setSelected(prev => withAll(prev, fs.map(findingKey), on))

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">◆</span>
          <span>SBOM Fixer</span>
        </div>
        <div className="path" title={root}>
          {root ? (
            <>
              <span className="path-label">레포</span>
              <span className="path-value">{root}</span>
            </>
          ) : (
            <span className="muted">분석할 폴더를 선택하세요</span>
          )}
        </div>
        <div className="actions">
          <button onClick={pickFolder} disabled={!!busy}>폴더 선택</button>
          {root && (
            <>
              <button onClick={() => runScan(root)} disabled={!!busy}>다시 분석</button>
              <button onClick={() => openInFinder(root)} className="ghost">Finder에서 열기</button>
            </>
          )}
        </div>
      </header>

      {error && (
        <div className="banner error">
          <span>{error}</span>
          <button className="link" onClick={() => setError('')}>닫기</button>
        </div>
      )}

      <main className="content">
        {busy && (
          <div className="busy">
            <div className="spinner" />
            <div>
              <div className="busy-title">{busy === 'scan' ? 'SBOM 분석 중' : '패키지 수정 중'}</div>
              <div className="muted">{progress}</div>
            </div>
          </div>
        )}

        {!report && !busy && (
          <div className="empty">
            <div className="empty-icon">⌗</div>
            <h1>레포지토리의 의존성을 분석하고 취약점을 수정합니다</h1>
            <p className="muted">
              package-lock.json (npm), go.mod (Go), requirements*.txt (Python)을 찾아 SBOM을 만들고,
              OSV.dev 취약점 DB와 대조합니다.
            </p>
            <button className="primary big" onClick={pickFolder}>폴더 선택</button>
            <p className="muted small">또는 폴더를 이 창으로 끌어다 놓으세요</p>
          </div>
        )}

        {report && !busy && (
          <>
            <Summary report={report} />

            {(!report.gitRepo || (report.gitDirty?.length ?? 0) > 0 || (report.warnings?.length ?? 0) > 0) && (
              <div className="notices">
                {!report.gitRepo && (
                  <div className="banner warn">
                    Git 저장소가 아닙니다. 수정 내용을 되돌리기 어려우니 백업 후 진행하세요.
                  </div>
                )}
                {(report.gitDirty?.length ?? 0) > 0 && (
                  <div className="banner warn">
                    커밋되지 않은 의존성 파일 변경이 있습니다: {report.gitDirty!.join(', ')}
                  </div>
                )}
                {(report.warnings?.length ?? 0) > 0 && (
                  <details className="banner info">
                    <summary>분석 경고 {report.warnings!.length}건</summary>
                    <ul>{report.warnings!.map((w, i) => <li key={i}>{w}</li>)}</ul>
                  </details>
                )}
              </div>
            )}

            <div className="tabs">
              <button className={tab === 'findings' ? 'tab active' : 'tab'} onClick={() => setTab('findings')}>
                조치 필요 <span className="count">{findings.length}</span>
              </button>
              <button className={tab === 'components' ? 'tab active' : 'tab'} onClick={() => setTab('components')}>
                전체 컴포넌트 (SBOM) <span className="count">{report.components.length}</span>
              </button>
              <div className="tab-actions">
                <span className="muted small">내보내기</span>
                {formats.map(f => (
                  <button key={f.id} className="ghost small-btn" onClick={() => doExport(f)} title={f.dialogTitle}>
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {tab === 'findings' ? (
              <FindingsTable findings={findings} selected={selected} onToggle={toggle} onSetMany={setMany} />
            ) : (
              <ComponentsTable components={report.components} findings={findings} />
            )}
          </>
        )}
      </main>

      {report && tab === 'findings' && !busy && findings.length > 0 && (
        <footer className="actionbar">
          <span>
            <b>{selectedFindings.length}</b>개 선택됨
            {selectedFindings.some(f => f.majorBump) && <span className="tag warn">메이저 버전 변경 포함</span>}
          </span>
          <div className="actions">
            <button className="ghost" onClick={() => setSelected(new Set())} disabled={selectedFindings.length === 0}>
              선택 해제
            </button>
            <button className="primary" disabled={selectedFindings.length === 0} onClick={() => setConfirming(true)}>
              선택 항목 수정
            </button>
          </div>
        </footer>
      )}

      {confirming && (
        <FixDialog findings={selectedFindings} onCancel={() => setConfirming(false)} onConfirm={runFix} />
      )}
      {fixReport && <ResultDialog report={fixReport} onClose={() => setFixReport(null)} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  )
}

function Summary({report}: {report: ScanReport}) {
  const vulnCount = countVulns(report.findings)
  return (
    <section className="summary">
      <div className="stat">
        <div className="stat-value">{report.components.length}</div>
        <div className="stat-label">컴포넌트</div>
        <div className="stat-sub">
          {Object.entries(report.ecosystems).map(([k, v]) => (
            <span key={k} className="chip">{k} {v}</span>
          ))}
        </div>
      </div>
      <div className="stat">
        <div className="stat-value">{report.findings.length}</div>
        <div className="stat-label">취약 패키지</div>
        <div className="stat-sub muted">취약점 {vulnCount}건</div>
      </div>
      <div className="stat sev-stats">
        {SEVERITIES.map(s => (
          <div key={s} className={`sev-stat sev-${s.toLowerCase()}`}>
            <div className="stat-value">{report.severities[s] ?? 0}</div>
            <div className="stat-label">{SEVERITY_LABEL[s]}</div>
          </div>
        ))}
      </div>
      <div className="stat meta muted">
        <div>매니페스트 {report.manifests?.length ?? 0}개</div>
        <div>{report.scannedAt}</div>
        <div>{(report.durationMs / 1000).toFixed(1)}초 소요</div>
      </div>
    </section>
  )
}
