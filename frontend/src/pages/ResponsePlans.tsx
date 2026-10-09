import { api, unwrap } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Spinner, fmt } from '../components/ui'

export default function ResponsePlans() {
  const { data, error, loading, reload } = useAsync(async () => unwrap<any[]>(await api('/response-plans/', { params: { size: 50 } })))
  const act = useAction()
  const go = async (id: number, verb: 'approve' | 'reject' | 'execute') => {
    if (verb === 'execute' && !confirm('Execute this plan? (Actions are simulated in this build.)')) return
    await act.run(() => api(`/response-plans/${id}/${verb}`, { method: 'POST', body: verb === 'reject' ? { reason: 'Rejected by analyst' } : undefined }))
    reload()
  }
  if (loading && !data) return <Spinner />
  return (
    <Page title="Response plans">
      <ErrorBox error={error ?? act.error} />
      <p className="text-sm text-slate-400">Plans are drafted from a case (Cases → open a case → “Draft response plan”). Containment on OT control, field and safety zones always needs a human approval.</p>
      {!data?.length && <div className="card text-center text-sm text-slate-500">No response plans yet.</div>}
      {data?.map((p) => (
        <div key={p.id} className="card space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2"><b>Plan #{p.id}</b><span className="text-sm text-slate-400">case #{p.case_id} · {p.autonomy_level} · {fmt(p.created_at)}</span><Badge value={p.status} /></div>
            <div className="flex gap-2">
              {p.status === 'pending_approval' && <><button className="btn" disabled={act.busy} onClick={() => go(p.id, 'approve')}>Approve</button><button className="btn-ghost" disabled={act.busy} onClick={() => go(p.id, 'reject')}>Reject</button></>}
              {p.status === 'approved' && <button className="btn" disabled={act.busy} onClick={() => go(p.id, 'execute')}>Execute</button>}
            </div>
          </div>
          {p.rationale && <p className="text-sm text-slate-300">{p.rationale}</p>}
          <ol className="space-y-1">{p.actions.map((a: any, i: number) => (
            <li key={i} className="flex flex-wrap items-center gap-2 rounded-lg bg-slate-800/50 px-3 py-2 text-sm">
              <span className="font-mono text-xs text-slate-500">{a.priority}</span><b>{a.action_type}</b><span className="text-slate-400">→ {a.target}</span>
              {a.policy_check?.requires_human ? <span className="rounded bg-yellow-500/20 px-1.5 text-xs text-yellow-200">needs approval</span> : <span className="rounded bg-emerald-500/20 px-1.5 text-xs text-emerald-300">auto</span>}
              {a.execution_result && <Badge value={a.execution_result.status} />}
              <span className="w-full text-xs text-slate-500">{a.reason} {a.policy_check && `— ${a.policy_check.reason}`}</span>
            </li>))}</ol>
        </div>))}
    </Page>
  )
}
