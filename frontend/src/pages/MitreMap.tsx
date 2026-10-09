import { useState } from 'react'
import { api, unwrap } from '../api'
import { useAsync } from '../hooks'
import { ErrorBox, Page, Spinner, Stat } from '../components/ui'

export default function MitreMap() {
  const [q, setQ] = useState('')
  const { data, error, loading } = useAsync(async () => {
    const [cov, techs] = await Promise.all([api('/mitre/coverage'), api<any[]>('/mitre/techniques')])
    return { cov: unwrap<any>(cov), techs }
  })
  const cases = useAsync(() => api('/cases/', { params: { size: 100 } }))
  if (loading) return <Spinner />
  if (error || !data) return <ErrorBox error={error} />
  const seen = new Set<string>((cases.data?.cases ?? []).flatMap((c: any) => (c.mitre_techniques ?? []).map((t: any) => t.id ?? t)))
  // per-technique highlighting uses the techniques attached to the user's cases
  const tactics = Object.entries(data.cov.by_tactic as Record<string, any>).filter(([, t]) => t.total > 0)
  const shown = data.techs.filter((t) => !q || (t.id + t.name).toLowerCase().includes(q.toLowerCase()))

  return (
    <Page title="MITRE ATT&CK coverage" actions={<input className="input w-56" placeholder="Search techniques…" value={q} onChange={(e) => setQ(e.target.value)} />}>
      <div className="grid grid-cols-3 gap-3"><Stat label="Techniques" value={data.cov.total_techniques} /><Stat label="Observed in cases" value={data.cov.covered_techniques} tone="text-indigo-300" /><Stat label="Coverage" value={`${data.cov.coverage_percentage}%`} /></div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{tactics.map(([id, t]) => (
        <div key={id} className="card"><div className="mb-1 flex justify-between text-sm"><span>{t.name}</span><span className="text-slate-400">{t.covered}/{t.total}</span></div>
          <div className="h-2 overflow-hidden rounded bg-slate-800"><div className="h-full bg-indigo-500" style={{ width: `${t.percentage}%` }} /></div></div>))}</div>
      <div className="card"><div className="flex flex-wrap gap-2">{shown.map((t) => (
        <span key={t.id} title={t.description} className={`rounded-lg border px-2 py-1 text-xs ${seen.has(t.id) ? 'border-indigo-500 bg-indigo-500/20 text-indigo-100' : 'border-slate-700 bg-slate-800/50 text-slate-400'}`}>
          <b className="font-mono">{t.id}</b> {t.name}</span>))}</div></div>
    </Page>
  )
}
