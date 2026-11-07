// Immutable Set helpers for checkbox selection state.

export function toggled<T>(set: ReadonlySet<T>, item: T): Set<T> {
  const next = new Set(set)
  if (next.has(item)) next.delete(item)
  else next.add(item)
  return next
}

export function withAll<T>(set: ReadonlySet<T>, items: Iterable<T>, on: boolean): Set<T> {
  const next = new Set(set)
  for (const i of items) {
    if (on) next.add(i)
    else next.delete(i)
  }
  return next
}
