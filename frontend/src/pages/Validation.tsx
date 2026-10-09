import { useState } from 'react'
import { api, unwrap } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Spinner, Stat, Table, fmt } from '../components/ui'

export default function Validation() {
  const techs = useAsync(() => api<any[]>('/validation/techniques'))
  const runs = useAsync(async () => unwrap<any[]>(await api('/validation/runs')))
  const [picked, setPicked] = useState<string[]>([])
  const [name, setName] = useState('Detection coverage check')
  const [detail, setDetail] = useState<any>(null)
  const act = useAction()

  const toggle = (id: string) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]))
  const start = async () => {
    const created = await act.run(async () => unwrap<any>(await api('/validation/runs', { body: { name, mitre_techniques: picked } })))
    if (!created) return
    await act.run(() => api(`/validation/runs/${created.id}/execute`, { method: 'POST' }))
    runs.reload(); open(created.id)
  }
  const open = async (id: number) => setDetail(unwrap(await api(`/validation/runs/${id}`)))

  return (
    <Page title="Purple-team validation">
      <p className="text-sm text-slate-400">Dry run: for each ATT&CK technique we check whether your own telemetry already contains evidence that your sensors would see it. Nothing is executed against your network.</p>
      <ErrorBox error={act.error} />
      <div className="card space-y-3">
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
        {!techs.data ? <Spinner /> : <div className="flex flex-wrap gap-2">{techs.data.map((t) => (
          <button key={t.id} onClick={() => toggle(t.id)} className={`rounded-lg border px-2 py-1 text-xs ${picked.includes(t.id) ? 'border-indigo-500 bg-indigo-500/20 text-indigo-100' : 'border-slate-700 text-slate-400'}`}><b className="font-mono">{t.id}</b> {t.name}</button>))}</div>}
        <button className="btn" disabled={act.busy || !picked.length} onClick={start}>Run validation ({picked.length})</button>
      </div>
      {detail && <div className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-300">{detail.name}</h2>
        {detail.results_summary && <div className="grid grid-cols-4 gap-3"><Stat label="Tests" value={detail.results_summary.tested} /><Stat label="Detected" value={detail.results_summary.detected} tone="text-emerald-300" /><Stat label="Missed" value={detail.results_summary.missed} tone="text-red-300" /><Stat label="Rate" value={`${detail.results_summary.detection_rate}%`} /></div>}
        <Table rows={detail.steps} cols={[{ head: 'Technique', cell: (s: any) => `${s.technique_id} ${s.technique_name}` }, { head: 'Test', cell: (s: any) => s.test_name }, { head: 'Expected detection', cell: (s: any) => s.expected_detection }, { head: 'Result', cell: (s: any) => <Badge value={s.result} /> }, { head: 'Evidence', cell: (s: any) => `${s.evidence?.event_ids?.length ?? 0} events` }]} />
      </div>}
      <h2 className="text-sm font-semibold text-slate-300">Previous runs</h2>
      <Table rows={runs.data ?? []} onRow={(r: any) => open(r.id)} empty="No runs yet." cols={[{ head: 'Name', cell: (r: any) => r.name }, { head: 'Status', cell: (r: any) => <Badge value={r.status} /> }, { head: 'Detection rate', cell: (r: any) => (r.results_summary ? `${r.results_summary.detection_rate}%` : '—') }, { head: 'Created', cell: (r: any) => fmt(r.created_at) }]} />
    </Page>
  )
}
