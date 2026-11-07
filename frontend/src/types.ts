// Domain types mirrored from the Go JSON structs.

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

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: '치명',
  HIGH: '높음',
  MEDIUM: '보통',
  LOW: '낮음',
  UNKNOWN: '미상',
}
