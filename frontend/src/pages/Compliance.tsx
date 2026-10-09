import { useState } from 'react'
import { api, unwrap } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Spinner, Table } from '../components/ui'

const STATUSES = ['compliant', 'partial', 'non_compliant', 'not_applicable', 'not_assessed']

export default function Compliance() {
  const [fw, setFw] = useState<number | null>(null)
  const { data, error, loading, reload } = useAsync(async () => {
    const [frameworks, summary, assessments] = await Promise.all([api<any[]>('/compliance/frameworks'), api<any[]>('/compliance/summary'), api<any[]>('/compliance/assessments')])
    return { frameworks, summary, assessments }
  })
  const controls = useAsync(async () => (fw ?? data?.frameworks[0]?.id ? api<any[]>(`/compliance/frameworks/${fw ?? data!.frameworks[0].id}/controls`) : []), [fw, data?.frameworks.length])
  const act = useAction()

  const assess = async () => { await act.run(() => api('/compliance/assess', { method: 'POST' })); reload() }
  const setStatus = async (controlPk: number, status: string, prev: string, isAutomated: boolean) => {
    if (status === prev) return  // selecting the same value must never fire a write (some browsers re-fire onChange)
    if (isAutomated && !window.confirm(
      'This control is currently auto-assessed from real platform telemetry. Overriding it by hand replaces that ' +
      'evidence with a manual note, and "Run automated assessment" will never touch it again. Continue?'
    )) return
    await act.run(() => api(`/compliance/controls/${controlPk}/assessment`, { method: 'PUT', body: { status, evidence_detail: 'Set manually' } })); reload()
  }
  if (loading && !data) return <Spinner />
  if (error || !data) return <ErrorBox error={error} />
  const byControl = new Map(data.assessments.map((a: any) => [a.control_id, a]))
  const current = fw ?? data.frameworks[0]?.id

  return (
    <Page title="Compliance" actions={<button className="btn" onClick={assess} disabled={act.busy}>Run automated assessment</button>}>
      <ErrorBox error={act.error} />
      <div className="grid gap-3 sm:grid-cols-2">{data.summary.map((s: any) => (
        <button key={s.framework_id} onClick={() => setFw(s.framework_id)} className={`card text-left ${current === s.framework_id ? 'border-indigo-500' : ''}`}>
          <div className="flex justify-between"><b>{s.framework_name}</b><span className="text-lg font-semibold">{s.compliance_percentage}%</span></div>
          <div className="my-2 h-2 overflow-hidden rounded bg-slate-800"><div className="h-full bg-emerald-500" style={{ width: `${s.compliance_percentage}%` }} /></div>
          <div className="text-xs text-slate-400">{s.compliant} compliant · {s.partial} partial · {s.non_compliant} non-compliant · {s.not_assessed} not assessed</div></button>))}</div>
      <Table rows={controls.data ?? []} cols={[
        { head: 'Control', cell: (c: any) => <span className="font-mono text-xs">{c.control_id}</span> }, { head: 'Title', cell: (c: any) => c.title },
        { head: 'Category', cell: (c: any) => <span className="text-xs text-slate-400">{c.category}</span> },
        { head: 'Status', cell: (c: any) => { const a: any = byControl.get(c.id); const cur = a?.status ?? 'not_assessed'
          return <select className="input w-auto py-0.5" value={cur} onChange={(e) => setStatus(c.id, e.target.value, cur, a?.assessed_by === 'system')}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select> } },
        { head: 'Evidence', cell: (c: any) => { const a: any = byControl.get(c.id); return a ? <span className="text-xs text-slate-400">{a.evidence_detail} <Badge value={a.assessed_by === 'system' ? 'automated' : 'manual'} /></span> : '' } },
      ]} />
    </Page>
  )
}
