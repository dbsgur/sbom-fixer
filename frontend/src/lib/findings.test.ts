import {describe, expect, it} from 'vitest'
import type {Finding} from '../types'
import {
  componentKey, countVulns, ecosystemsOf, EMPTY_FILTER, filterFindings, findingKey, fixPlan, jsPackageManager, manifestsOf,
  matchesQuery, toFixRequest,
} from './findings'

function finding(over: Partial<Finding> & {name: string; ecosystem?: string; direct?: boolean; manifest?: string}): Finding {
  const {name, ecosystem = 'npm', direct = true, manifest = 'package-lock.json', ...rest} = over
  return {
    component: {name, version: '1.0.0', ecosystem, purl: '', manifest, direct, dev: false},
    vulns: [{id: `GHSA-${name}`, aliases: [`CVE-2024-${name}`], summary: '', severity: 'HIGH', fixedVersion: '1.0.1', url: ''}],
    severity: 'HIGH',
    fixVersion: '1.0.1',
    fixable: true,
    fullyFixed: true,
    majorBump: false,
    targetVulnerable: false,
    ...rest,
  }
}

const lodash = finding({name: 'lodash'})
const minimist = finding({name: 'minimist', severity: 'CRITICAL', direct: false})
const text = finding({name: 'golang.org/x/text', ecosystem: 'Go', manifest: 'svc/go.mod', fixable: false, fixVersion: ''})
const all = [lodash, minimist, text]

describe('keys', () => {
  it('are unique per ecosystem, manifest, name and version', () => {
    expect(findingKey(lodash)).toBe('npm|package-lock.json|lodash@1.0.0')
    expect(componentKey(text.component)).toBe('Go|svc/go.mod|golang.org/x/text@1.0.0')
  })
})

describe('matchesQuery', () => {
  it('matches name, advisory id and aliases case-insensitively', () => {
    expect(matchesQuery(lodash, 'LODA')).toBe(true)
    expect(matchesQuery(lodash, 'ghsa-lodash')).toBe(true)
    expect(matchesQuery(lodash, 'cve-2024-lodash')).toBe(true)
    expect(matchesQuery(lodash, 'react')).toBe(false)
  })

  it('treats blank query as match-all and tolerates null aliases', () => {
    const noAliases = finding({name: 'x', vulns: [{id: 'A', aliases: null, summary: '', severity: 'LOW', fixedVersion: '', url: ''}]})
    expect(matchesQuery(noAliases, '   ')).toBe(true)
    expect(matchesQuery(noAliases, 'cve')).toBe(false)
  })
})

describe('filterFindings', () => {
  it('returns everything with the empty filter', () => {
    expect(filterFindings(all, EMPTY_FILTER)).toHaveLength(3)
  })

  it.each([
    [{severity: 'CRITICAL' as const}, ['minimist']],
    [{ecosystem: 'Go'}, ['golang.org/x/text']],
    [{fixableOnly: true}, ['lodash', 'minimist']],
    [{query: 'mini', fixableOnly: true}, ['minimist']],
    [{severity: 'LOW' as const}, []],
  ])('filter %o', (partial, names) => {
    const got = filterFindings(all, {...EMPTY_FILTER, ...partial}).map(f => f.component.name)
    expect(got).toEqual(names)
  })
})

describe('aggregations', () => {
  it('collects ecosystems and manifests without duplicates', () => {
    expect(ecosystemsOf(all)).toEqual(['npm', 'Go'])
    expect(manifestsOf(all)).toEqual(['package-lock.json', 'svc/go.mod'])
  })

  it('counts vulnerabilities across findings', () => {
    expect(countVulns(all)).toBe(3)
    expect(countVulns([])).toBe(0)
  })
})

describe('toFixRequest', () => {
  it('maps a finding to the backend request shape', () => {
    expect(toFixRequest(minimist)).toEqual({
      ecosystem: 'npm',
      name: 'minimist',
      currentVersion: '1.0.0',
      targetVersion: '1.0.1',
      manifest: 'package-lock.json',
      direct: false,
    })
  })
})

describe('jsPackageManager', () => {
  it('is chosen by lock file name and defaults to npm', () => {
    expect(jsPackageManager('a/b/yarn.lock').override).toBe('resolutions')
    expect(jsPackageManager('pnpm-lock.yaml').override).toBe('pnpm.overrides')
    expect(jsPackageManager('package-lock.json').override).toBe('overrides')
    expect(jsPackageManager('weird.lock').override).toBe('overrides')
  })
})

describe('fixPlan', () => {
  it('describes the action per ecosystem', () => {
    expect(fixPlan(lodash)).toContain('의존성 버전 변경')
    expect(fixPlan(minimist)).toContain('overrides')
    expect(fixPlan(finding({name: 'a', direct: false, manifest: 'web/yarn.lock'}))).toBe('package.json resolutions 추가 → yarn install')
    expect(fixPlan(finding({name: 'a', manifest: 'pnpm-lock.yaml'}))).toBe(
      'package.json 의존성 버전 변경 → pnpm install --lockfile-only',
    )
    expect(fixPlan(finding({name: 'a', direct: false, manifest: 'pnpm-lock.yaml'}))).toContain('pnpm.overrides')
    expect(fixPlan(finding({name: 'golang.org/x/net', ecosystem: 'Go', fixVersion: 'v0.33.0'}))).toBe(
      'go get golang.org/x/net@v0.33.0 → go mod tidy',
    )
    expect(fixPlan(finding({name: 'requests', ecosystem: 'PyPI', manifest: 'requirements.txt'}))).toContain('requirements.txt')
    expect(fixPlan(finding({name: 'serde', ecosystem: 'crates.io'}))).toBe('')
    expect(fixPlan(finding({name: 'requests', ecosystem: 'PyPI', manifest: 'ml/poetry.lock', fixVersion: '2.33.0'}))).toBe(
      'pyproject.toml 선언을 2.33.0로 변경 (제약 형식 유지) → poetry add --lock',
    )
    expect(fixPlan(finding({name: 'urllib3', ecosystem: 'PyPI', manifest: 'poetry.lock', direct: false}))).toContain('poetry update urllib3')
    expect(fixPlan(finding({name: 'requests', ecosystem: 'PyPI', manifest: 'uv.lock', fixVersion: '2.33.0'}))).toContain('uv add --no-sync')
    expect(fixPlan(finding({name: 'urllib3', ecosystem: 'PyPI', manifest: 'uv.lock', direct: false, fixVersion: '2.8.0'}))).toBe(
      'uv lock --upgrade-package urllib3==2.8.0',
    )
  })
})
