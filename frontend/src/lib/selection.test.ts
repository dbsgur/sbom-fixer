import {describe, expect, it} from 'vitest'
import {toggled, withAll} from './selection'

describe('selection helpers', () => {
  it('toggled adds and removes without mutating the input', () => {
    const base = new Set(['a'])
    const added = toggled(base, 'b')
    const removed = toggled(added, 'a')
    expect([...added]).toEqual(['a', 'b'])
    expect([...removed]).toEqual(['b'])
    expect([...base]).toEqual(['a'])
  })

  it('withAll selects or clears many at once', () => {
    const on = withAll(new Set(['x']), ['a', 'b'], true)
    expect([...on].sort()).toEqual(['a', 'b', 'x'])
    expect([...withAll(on, ['a', 'x'], false)]).toEqual(['b'])
  })
})
