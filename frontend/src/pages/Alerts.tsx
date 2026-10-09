import { useState } from 'react'
import { api } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Pager, Spinner, Table, fmt } from '../components/ui'

export default function Alerts() {
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [open, setOpen] = useState<any>(null)
  const { data, error, loading, reload } = useAsync(() => api('/alerts/', { params: { page, size: 15, severity, status } }), [page, severity, status])
  const act = useAction()

  const ack = async (id: number) => { await act.run(() => api(`/alerts/${id}/acknowledge`, { method: 'POST' })); setOpen(null); reload() }
  const select = async (a: any) => {
    setOpen({ ...a, steps: null })
    const r = await api(`/alerts/${a.id}/remediations`)
    setOpen((cur: any) => (cur?.id === a.id ? { ...cur, steps: r.data } : cur))
  }

  return (
    <Page title="Vulnerability alerts" actions={<>
      <select className="input w-auto" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}>
        <option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s}>{s}</option>)}</select>
      <select className="input w-auto" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }}>
        <option value="">All statuses</option>{['pending', 'acknowledged', 'resolved', 'dismissed'].map((s) => <option key={s}>{s}</option>)}</select>
    </>}>
      <ErrorBox error={error ?? act.error} />
      {loading && !data ? <Spinner /> : data && (<>
        <Table rows={data.alerts} onRow={select} empty="No confirmed security alerts" cols={[
          { head: 'CVE', cell: (a: any) => <span className="font-mono text-xs">{a.cve_id ?? '—'}</span> },
          { head: 'Title', cell: (a: any) => <>{a.title}{a.known_exploited && <span className="ml-2 rounded bg-red-600 px-1.5 text-[10px] font-bold text-white">KEV</span>}</> },
          { head: 'Asset', cell: (a: any) => a.asset_name },
          { head: 'CVSS', cell: (a: any) => a.cvss_score ?? '—' },
          { head: 'Severity', cell: (a: any) => <Badge value={a.severity} /> },
          { head: 'Status', cell: (a: any) => <Badge value={a.status} /> },
          { head: 'Source', cell: (a: any) => <span className="text-xs text-slate-400">{a.source_label}</span> },
          { head: 'Created', cell: (a: any) => fmt(a.created_at) },
        ]} />
        <Pager page={page} pages={data.pages} onPage={setPage} />
      </>)}
      {open && (
        <div className="fixed inset-0 z-20 flex justify-end bg-black/50" onClick={() => setOpen(null)}>
          <div className="h-full w-full max-w-lg overflow-y-auto border-l border-slate-800 bg-slate-950 p-5" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-start justify-between gap-2"><h2 className="text-lg font-semibold text-white">{open.title}</h2><button className="btn-ghost" onClick={() => setOpen(null)}>Close</button></div>
            <div className="mb-3 flex gap-2"><Badge value={open.severity} /><Badge value={open.status} /></div>
            <p className="mb-4 text-sm text-slate-300">{open.description}</p>
            <dl className="mb-4 grid grid-cols-2 gap-2 text-sm">
              <dt className="text-slate-400">Asset</dt><dd>{open.asset_name}</dd>
              <dt className="text-slate-400">CVE</dt><dd className="font-mono">{open.cve_id}</dd>
              <dt className="text-slate-400">CVSS</dt><dd>{open.cvss_score ?? '—'}</dd>
              <dt className="text-slate-400">Detection rule</dt><dd>{open.detection_rule}</dd>
              <dt className="text-slate-400">Source</dt><dd>{open.source_label}</dd>
              <dt className="text-slate-400">Evidence</dt><dd>{open.source_url ? <a className="text-indigo-300 underline" href={open.source_url} target="_blank" rel="noreferrer">{open.source_url}</a> : '—'}</dd>
            </dl>
            <h3 className="mb-2 text-sm font-semibold text-slate-300">Suggested remediation</h3>
            {!open.steps ? <Spinner /> : <ol className="space-y-2">{open.steps.map((s: any) => (
              <li key={s.id} className="card text-sm"><div className="mb-1"><Badge value={s.action_type} /> {s.requires_maintenance_window && <span className="text-xs text-yellow-300">maintenance window</span>}</div>{s.description}</li>))}</ol>}
            {open.status === 'pending' && <button className="btn mt-4" disabled={act.busy} onClick={() => ack(open.id)}>Acknowledge</button>}
          </div>
        </div>
      )}
    </Page>
  )
}
