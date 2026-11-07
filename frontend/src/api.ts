// Thin typed wrapper around the generated Wails bindings.
import * as Go from '../wailsjs/go/main/App'
import {fixer} from '../wailsjs/go/models'
import {BrowserOpenURL, EventsOff, EventsOn, OnFileDrop, OnFileDropOff} from '../wailsjs/runtime/runtime'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'

export interface Component {
  name: string
  version: string
  ecosystem: string
  purl: string
  manifest: string
  direct: boolean
  dev: boolean
}

export interface Vulnerability {
  id: string
  aliases: string[] | null
  summary: string
  severity: Severity
  fixedVersion: string
  url: string
}

export interface Finding {
  component: Component
  vulns: Vulnerability[]
  severity: Severity
  fixVersion: string
  fixable: boolean
  fullyFixed: boolean
  majorBump: boolean
  targetVulnerable: boolean
}

export interface ScanReport {
  root: string
  components: Component[]
  findings: Finding[]
  manifests: string[] | null
  warnings: string[] | null
  ecosystems: Record<string, number>
  severities: Record<string, number>
  gitRepo: boolean
  gitDirty: string[] | null
  scannedAt: string
  durationMs: number
}

export interface FixRequest {
  ecosystem: string
  name: string
  currentVersion: string
  targetVersion: string
  manifest: string
  direct: boolean
}

export interface FixResult {
  request: FixRequest
  success: boolean
  message: string
}

export interface CommandLog {
  dir: string
  command: string
  output: string
  success: boolean
}

export interface FixReport {
  fix: {results: FixResult[]; commands: CommandLog[] | null; changedFiles: string[] | null}
  rescan: ScanReport | null
}

export const selectFolder = (): Promise<string> => Go.SelectFolder()
export const scan = (root: string) => Go.Scan(root) as unknown as Promise<ScanReport>
export const applyFixes = (root: string, reqs: FixRequest[]) =>
  Go.ApplyFixes(root, reqs.map(r => fixer.Request.createFrom(r))) as unknown as Promise<FixReport>
export const exportSBOM = (): Promise<string> => Go.ExportSBOM()
export const openInFinder = (p: string) => Go.OpenInFinder(p)
export const openURL = (u: string) => BrowserOpenURL(u)
export const initialPath = (): Promise<string> => Go.InitialPath()

// Calls cb with the folder that was dropped onto the window.
export function onFolderDrop(cb: (dir: string) => void): () => void {
  OnFileDrop(async (_x, _y, paths) => {
    if (paths.length === 0) return
    const dir = await Go.ResolveDroppedPath(paths[0])
    if (dir) cb(dir)
  }, false)
  return () => OnFileDropOff()
}

export function onProgress(cb: (msg: string) => void): () => void {
  EventsOn('progress', cb)
  return () => EventsOff('progress')
}

export const findingKey = (f: Finding) =>
  `${f.component.ecosystem}|${f.component.manifest}|${f.component.name}@${f.component.version}`

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: '치명',
  HIGH: '높음',
  MEDIUM: '보통',
  LOW: '낮음',
  UNKNOWN: '미상',
}
