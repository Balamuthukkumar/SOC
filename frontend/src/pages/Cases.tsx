import { useNavigate } from 'react-router-dom'
import { Play, Sparkles } from 'lucide-react'
import { useState } from 'react'
import { api, unwrap } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Spinner, Table, fmt } from '../components/ui'

export default function Cases() {
  const nav = useNavigate()
  const { data, error, loading, reload } = useAsync(() => api('/cases/', { params: { size: 50 } }))
  const [note, setNote] = useState<string | null>(null)
  const act = useAction()

  const pipeline = async () => {
    const r = await act.run(() => api('/cases/pipeline', { method: 'POST', params: { hours_back: 168 } }))
    if (r) { const d = unwrap<any>(r); setNote(`Detect: ${d.detect.summary ?? d.detect.error}. Triage: ${d.triage.summary ?? d.triage.error}.`); reload() }
  }
  const triage = async () => {
    const r = await act.run(() => api('/cases/auto-triage', { method: 'POST', params: { hours_back: 168 } }))
    if (r) { setNote(unwrap<any>(r).summary); reload() }
  }

  return (
    <Page title="Investigations" actions={<>
      <button className="btn-ghost" onClick={triage} disabled={act.busy}><Sparkles size={14} /> Auto-triage</button>
      <button className="btn" onClick={pipeline} disabled={act.busy}><Play size={14} /> Run detect + triage</button>
    </>}>
      <ErrorBox error={error ?? act.error} />
      {note && <div className="rounded-lg border border-indigo-500/40 bg-indigo-500/10 p-3 text-sm text-indigo-200">{note}</div>}
      {loading && !data ? <Spinner /> : data && (
        <Table rows={data.cases} onRow={(c: any) => nav(`/cases/${c.id}`)} empty="No cases yet. Run detect + triage to create them from alerts and events." cols={[
          { head: 'Title', cell: (c: any) => c.title }, { head: 'Severity', cell: (c: any) => <Badge value={c.severity} /> },
          { head: 'Status', cell: (c: any) => <Badge value={c.status} /> },
          { head: 'Confidence', cell: (c: any) => (c.confidence_score != null ? `${Math.round(c.confidence_score * 100)}%` : '—') },
          { head: 'Alerts', cell: (c: any) => c.alert_count }, { head: 'Events', cell: (c: any) => c.event_count },
          { head: 'By', cell: (c: any) => c.created_by }, { head: 'Created', cell: (c: any) => fmt(c.created_at) },
        ]} />
      )}
    </Page>
  )
}
