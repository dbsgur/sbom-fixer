import {SEVERITY_LABEL, Severity} from '../types'

export default function SeverityBadge({s}: {s: Severity}) {
  return <span className={`sev sev-${s.toLowerCase()}`}>{SEVERITY_LABEL[s]}</span>
}
