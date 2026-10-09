import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ShieldAlert } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { api, unwrap } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Spinner, Table, fmt } from '../components/ui'

const STATUSES = ['open', 'investigating', 'resolved', 'closed', 'false_positive']

export default function CaseDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const { data, error, loading, reload } = useAsync(async () => {
    const [c, alerts, events, blast, similar] = await Promise.all([
      api(`/cases/${id}`), api(`/cases/${id}/alerts`), api(`/cases/${id}/events`),
      api(`/cases/${id}/blast-radius`), api(`/cases/${id}/similar`),
    ])
    return { c, alerts, events, blast: unwrap<any>(blast), similar: unwrap<any[]>(similar) }
  }, [id])
  const act = useAction()

  if (loading && !data) return <Spinner />
  if (error || !data) return <ErrorBox error={error} />
  const { c, alerts, events, blast, similar } = data

  const setStatus = async (status: string) => { await act.run(() => api(`/cases/${id}`, { method: 'PATCH', body: { status } })); reload() }
  const makePlan = async () => {
    const r = await act.run(() => api('/response-plans/generate', { method: 'POST', params: { case_id: id } }))
    if (r) nav('/response')
  }

  return (
    <Page title={c.title} actions={<>
      <Link to="/cases" className="btn-ghost"><ArrowLeft size={14} /> Cases</Link>
      <select className="input w-auto" value={c.status} onChange={(e) => setStatus(e.target.value)}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select>
      <button className="btn" onClick={makePlan} disabled={act.busy}><ShieldAlert size={14} /> Draft response plan</button>
    </>}>
      <ErrorBox error={act.error} />
      <div className="flex flex-wrap items-center gap-2"><Badge value={c.severity} /><Badge value={c.status} />
        {c.confidence_score != null && <span className="text-sm text-slate-400">confidence {Math.round(c.confidence_score * 100)}%</span>}</div>
      {c.summary && <div className="card text-sm">{c.summary}</div>}
      {c.attack_narrative && <div className="card"><h2 className="mb-1 text-sm font-semibold text-slate-300">Attack narrative</h2><p className="text-sm text-slate-300">{c.attack_narrative}</p></div>}

      <div className="grid gap-3 lg:grid-cols-2">
        <div className="card"><h2 className="mb-2 text-sm font-semibold text-slate-300">MITRE ATT&CK techniques</h2>
          <div className="flex flex-wrap gap-2">{(c.mitre_techniques ?? []).map((t: any) => (
            <span key={t.id ?? t} className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs"><b className="font-mono text-indigo-300">{t.id ?? t}</b> {t.name}{t.confidence != null && <span className="text-slate-400"> · {Math.round(t.confidence * 100)}%</span>}</span>))}
            {!c.mitre_techniques?.length && <span className="text-sm text-slate-500">None mapped.</span>}</div></div>
        <div className="card"><h2 className="mb-2 text-sm font-semibold text-slate-300">Blast radius</h2>
          <div className="mb-2 grid grid-cols-4 gap-2 text-center text-sm">{[['Assets', blast.summary.assets_affected], ['OT assets', blast.summary.ot_assets_affected], ['IPs', blast.summary.ips_involved], ['Techniques', blast.summary.techniques_used]].map(([l, v]) => (
            <div key={l as string}><div className="text-xl font-semibold text-white">{v}</div><div className="text-xs text-slate-400">{l}</div></div>))}</div>
          <div className="flex flex-wrap gap-1">{blast.nodes.filter((n: any) => n.type === 'asset').map((n: any) => <span key={n.id} className={`rounded px-2 py-0.5 text-xs ${n.is_ot ? 'bg-red-500/20 text-red-300' : 'bg-slate-800'}`}>{n.label}</span>)}</div></div>
      </div>

      <div className="card"><h2 className="mb-3 text-sm font-semibold text-slate-300">Timeline</h2>
        <ol className="space-y-2 border-l border-slate-700 pl-4">{c.timeline.map((t: any) => (
          <li key={t.id} className="text-sm"><span className="text-xs text-slate-500">{fmt(t.timestamp)} · {t.entry_type} · {t.source}</span><div>{t.content}</div></li>))}</ol></div>

      <h2 className="text-sm font-semibold text-slate-300">Linked alerts</h2>
      <Table rows={alerts} cols={[{ head: 'Alert', cell: (a: any) => a.title }, { head: 'Severity', cell: (a: any) => <Badge value={a.severity} /> }, { head: 'Asset', cell: (a: any) => a.asset_name }]} empty="No linked alerts." />
      <h2 className="text-sm font-semibold text-slate-300">Linked events</h2>
      <Table rows={events} cols={[{ head: 'Time', cell: (e: any) => fmt(e.timestamp) }, { head: 'Severity', cell: (e: any) => <Badge value={e.severity} /> }, { head: 'Signature', cell: (e: any) => e.signature ?? e.event_type },
        { head: 'Flow', cell: (e: any) => <span className="font-mono text-xs">{e.source_ip} → {e.dest_ip}{e.dest_port ? `:${e.dest_port}` : ''}</span> }, { head: 'Action', cell: (e: any) => e.action ?? '' }]} empty="No linked events." />
      {similar.length > 0 && <><h2 className="text-sm font-semibold text-slate-300">Similar cases</h2>
        <Table rows={similar} cols={[{ head: 'Case', cell: (s: any) => <Link className="text-indigo-300" to={`/cases/${s.case_id}`}>{s.title}</Link> }, { head: 'Similarity', cell: (s: any) => `${Math.round(s.similarity * 100)}%` }]} /></>}
    </Page>
  )
}
