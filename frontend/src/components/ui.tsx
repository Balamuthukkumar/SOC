import type { ReactNode } from 'react'
import { Loader2 } from 'lucide-react'

const SEV: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/40',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
  medium: 'bg-yellow-500/20 text-yellow-200 border-yellow-500/40',
  low: 'bg-sky-500/20 text-sky-300 border-sky-500/40',
  info: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
}
const OK = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
const STATUS: Record<string, string> = {
  compliant: OK, completed: OK, approved: OK, detected: OK, acknowledged: OK, resolved: OK, active: OK,
  non_compliant: SEV.critical, failed: SEV.critical, rejected: SEV.critical, missed: SEV.critical,
  partial: SEV.medium, pending: SEV.medium, pending_approval: SEV.medium, investigating: SEV.medium, open: SEV.high,
}

export function Badge({ value }: { value?: string | null }) {
  if (!value) return <span className="text-slate-500">—</span>
  const cls = SEV[value] ?? STATUS[value] ?? SEV.info
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${cls}`}>{value.replace(/_/g, ' ')}</span>
}

export function Spinner() {
  return <div className="flex justify-center p-8 text-slate-400"><Loader2 className="animate-spin" /></div>
}

export function ErrorBox({ error }: { error: string | null }) {
  return error ? <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">{error}</div> : null
}

export function Page({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold text-white">{title}</h1>
        <div className="flex gap-2">{actions}</div>
      </div>
      {children}
    </div>
  )
}

export function Table<T>({ rows, cols, onRow, empty = 'Nothing here yet.' }: {
  rows: T[]; cols: { head: string; cell: (r: T) => ReactNode; className?: string }[]; onRow?: (r: T) => void; empty?: string
}) {
  if (!rows.length) return <div className="card text-center text-sm text-slate-500">{empty}</div>
  return (
    <div className="card overflow-x-auto p-0">
      <table className="w-full">
        <thead className="border-b border-slate-800"><tr>{cols.map((c) => <th key={c.head} className="th">{c.head}</th>)}</tr></thead>
        <tbody className="divide-y divide-slate-800/60">
          {rows.map((r, i) => (
            <tr key={i} onClick={onRow ? () => onRow(r) : undefined} className={onRow ? 'cursor-pointer hover:bg-slate-800/50' : ''}>
              {cols.map((c) => <td key={c.head} className={`td ${c.className ?? ''}`}>{c.cell(r)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="card">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${tone ?? 'text-white'}`}>{value}</div>
    </div>
  )
}

export function Pager({ page, pages, onPage }: { page: number; pages: number; onPage: (p: number) => void }) {
  if (pages <= 1) return null
  return (
    <div className="flex items-center justify-end gap-2 text-sm">
      <button className="btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>Prev</button>
      <span className="text-slate-400">{page} / {pages}</span>
      <button className="btn-ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  )
}

// Local time plus explicit UTC offset, e.g. "Oct 9, 2026, 6:20 PM (UTC+5:30)" — never bare numeric
// day/month, which reads differently depending on the viewer's locale.
const tzOffset = () => {
  const mins = -new Date().getTimezoneOffset()
  const sign = mins >= 0 ? '+' : '-'
  const abs = Math.abs(mins)
  return `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`
}

export const fmt = (d?: string | null) => {
  if (!d) return '—'
  // The API sends naive ISO timestamps (no "Z"/offset) — every one of them is UTC (utcnow() on the
  // backend). Without a designator, JS Date treats the string as already-local and skips conversion
  // entirely, so append "Z" when one isn't present before parsing.
  const iso = /[Zz]|[+-]\d\d:?\d\d$/.test(d) ? d : `${d}Z`
  const date = new Date(iso)
  const local = date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true,
  })
  return `${local} (${tzOffset()})`
}
