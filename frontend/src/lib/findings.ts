// Pure helpers for working with findings. No React, no Wails.
import type {Component, Finding, FixRequest, Severity} from '../types'

export const componentKey = (c: Component) => `${c.ecosystem}|${c.manifest}|${c.name}@${c.version}`

export const findingKey = (f: Finding) => componentKey(f.component)

export interface FindingFilter {
  query: string
  severity: Severity | 'ALL'
  ecosystem: string
  fixableOnly: boolean
}

export const EMPTY_FILTER: FindingFilter = {query: '', severity: 'ALL', ecosystem: 'ALL', fixableOnly: false}

/** Matches package name, advisory id or any alias (CVE/GHSA), case-insensitively. */
export function matchesQuery(f: Finding, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  if (f.component.name.toLowerCase().includes(q)) return true
  return f.vulns.some(v => v.id.toLowerCase().includes(q) || (v.aliases ?? []).some(a => a.toLowerCase().includes(q)))
}

export function filterFindings(findings: Finding[], filter: FindingFilter): Finding[] {
  return findings.filter(f =>
    (filter.severity === 'ALL' || f.severity === filter.severity) &&
    (filter.ecosystem === 'ALL' || f.component.ecosystem === filter.ecosystem) &&
    (!filter.fixableOnly || f.fixable) &&
    matchesQuery(f, filter.query),
  )
}

export const ecosystemsOf = (findings: Finding[]) => Array.from(new Set(findings.map(f => f.component.ecosystem)))

export const countVulns = (findings: Finding[]) => findings.reduce((n, f) => n + f.vulns.length, 0)

export function toFixRequest(f: Finding): FixRequest {
  return {
    ecosystem: f.component.ecosystem,
    name: f.component.name,
    currentVersion: f.component.version,
    targetVersion: f.fixVersion,
    manifest: f.component.manifest,
    direct: f.component.direct,
  }
}

/** Human readable description of what a fix will do. */
export function fixPlan(f: Finding): string {
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

export const manifestsOf = (findings: Finding[]) => Array.from(new Set(findings.map(f => f.component.manifest)))
