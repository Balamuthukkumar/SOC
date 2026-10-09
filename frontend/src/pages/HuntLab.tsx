import { useState, type FormEvent } from 'react'
import { Search } from 'lucide-react'
import { api, unwrap } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Table, fmt } from '../components/ui'

const EXAMPLES = ['Unauthorized Modbus writes to PLCs', 'What did 203.0.113.42 do?', 'DNS beaconing to suspicious domains', 'Lateral movement over RDP or SMB']

export default function HuntLab() {
  const [hypothesis, setHypothesis] = useState('')
  const [result, setResult] = useState<any>(null)
  const sessions = useAsync(() => api<any[]>('/hunt/'))
  const act = useAction()

  const run = async (e?: FormEvent, h = hypothesis) => {
    e?.preventDefault()
    if (!h.trim()) return
    setHypothesis(h)
    const r = await act.run(() => api('/hunt/', { body: { hypothesis: h } }))
    if (r) { setResult(unwrap(r)); sessions.reload() }
  }

  return (
    <Page title="Threat hunting lab">
      <form onSubmit={run} className="card space-y-2">
        <div className="flex gap-2"><input className="input" placeholder="Describe what you want to hunt for…" value={hypothesis} onChange={(e) => setHypothesis(e.target.value)} />
          <button className="btn" disabled={act.busy || !hypothesis.trim()}><Search size={14} /> Hunt</button></div>
        <div className="flex flex-wrap gap-2">{EXAMPLES.map((x) => <button type="button" key={x} className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300 hover:bg-slate-700" onClick={() => run(undefined, x)}>{x}</button>)}</div>
      </form>
      <ErrorBox error={act.error} />
      {result && <div className="space-y-3">
        {result.explanation && <div className="card text-sm text-slate-300">{result.explanation}</div>}
        {result.query_results.map((q: any, i: number) => (
          <div key={i} className="space-y-1"><div className="flex items-center gap-2 text-sm font-medium"><span>{q.query.description ?? `Query ${i + 1}`}</span><span className="text-slate-500">{q.row_count} rows</span></div>
            {q.error ? <ErrorBox error={q.error} /> : <Table rows={q.rows} empty="No matching events." cols={Object.keys(q.rows[0] ?? {}).map((k) => ({
              head: k === 'is_synthetic' ? 'provenance' : k,
              cell: (r: any) => (
                k === 'is_synthetic' ? (r[k] ? <span className="rounded bg-yellow-600/30 px-1.5 text-[10px] font-bold text-yellow-200">TEST DATA</span> : <span className="text-xs text-emerald-400">real</span>)
                : k === 'severity' ? <Badge value={r[k]} />
                : k === 'timestamp' ? fmt(r[k])
                : <span className={k.includes('ip') ? 'font-mono text-xs' : ''}>{String(r[k] ?? '—')}</span>
              ) }))} />}
          </div>))}
        {result.sigma_rule && <pre className="card overflow-x-auto text-xs">{result.sigma_rule}</pre>}
      </div>}
      <h2 className="text-sm font-semibold text-slate-300">Recent hunts</h2>
      <Table rows={sessions.data ?? []} cols={[{ head: 'Hypothesis', cell: (s: any) => s.hypothesis }, { head: 'Queries', cell: (s: any) => s.queries_run }, { head: 'Findings', cell: (s: any) => s.findings_count }, { head: 'When', cell: (s: any) => fmt(s.created_at) }]} empty="No hunts yet." />
    </Page>
  )
}
