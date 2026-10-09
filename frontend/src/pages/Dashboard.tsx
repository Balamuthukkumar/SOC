import { Link } from 'react-router-dom'
import { Bar, BarChart, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, unwrap } from '../api'
import { useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Spinner, Stat, Table, fmt } from '../components/ui'

const COLORS: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#38bdf8', info: '#94a3b8' }

export default function Dashboard() {
  const { data, error, loading } = useAsync(async () => {
    const [alerts, list, events, ot, cases] = await Promise.all([
      api('/alerts/stats/overview'), api('/alerts/', { params: { size: 6 } }), api('/events/stats'),
      api('/ot/summary'), api('/cases/', { params: { size: 5 } }),
    ])
    return { alerts, list, events: unwrap<any>(events), ot, cases }
  })
  if (loading) return <Spinner />
  if (error || !data) return <ErrorBox error={error} />
  const { alerts, list, events, ot, cases } = data
  const sev = ['critical', 'high', 'medium', 'low'].map((s) => ({ name: s, value: alerts[`${s}_alerts`] }))
  const evSev = Object.entries(events.by_severity as Record<string, number>).map(([name, value]) => ({ name, value }))

  return (
    <Page title="Security posture">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Open alerts" value={alerts.pending_alerts} tone="text-orange-300" />
        <Stat label="Critical" value={alerts.critical_alerts} tone="text-red-400" />
        <Stat label="Security events" value={events.total_events} />
        <Stat label="OT discovery gap" value={ot.discovery_gap} tone={ot.discovery_gap ? 'text-yellow-300' : 'text-emerald-300'} />
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="card">
          <h2 className="mb-2 text-sm font-semibold text-slate-300">Alerts by severity</h2>
          {alerts.total_alerts === 0 ? (
            <div className="flex h-[200px] items-center justify-center text-center text-sm text-slate-500">No confirmed security alerts</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart><Pie data={sev} dataKey="value" nameKey="name" innerRadius={45} outerRadius={80} isAnimationActive={false} label={(e) => (e.value ? e.value : '')}>
                {sev.map((s) => <Cell key={s.name} fill={COLORS[s.name]} />)}
              </Pie><Legend /><Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} /></PieChart>
            </ResponsiveContainer>
          )}
        </div>
        <div className="card">
          <h2 className="mb-2 text-sm font-semibold text-slate-300">Events by severity</h2>
          {events.total_events === 0 ? (
            <div className="flex h-[200px] items-center justify-center text-center text-sm text-slate-500">No security events ingested yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={evSev}><XAxis dataKey="name" stroke="#64748b" /><YAxis stroke="#64748b" allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} cursor={{ fill: '#1e293b' }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]} isAnimationActive={false}>{evSev.map((s) => <Cell key={s.name} fill={COLORS[s.name]} />)}</Bar></BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <div><h2 className="mb-2 text-sm font-semibold text-slate-300">Latest alerts</h2>
          <Table rows={list.alerts} empty="No confirmed security alerts" cols={[{ head: 'Alert', cell: (a: any) => <span className="line-clamp-1">{a.title}</span> }, { head: 'Severity', cell: (a: any) => <Badge value={a.severity} /> }, { head: 'When', cell: (a: any) => fmt(a.created_at) }]} />
          <Link to="/alerts" className="mt-1 inline-block text-sm text-indigo-300">All alerts →</Link></div>
        <div><h2 className="mb-2 text-sm font-semibold text-slate-300">Recent cases</h2>
          <Table rows={cases.cases} empty="No confirmed cases — run detect + triage on the Cases page." cols={[{ head: 'Case', cell: (c: any) => <Link className="text-indigo-300" to={`/cases/${c.id}`}>{c.title}</Link> }, { head: 'Severity', cell: (c: any) => <Badge value={c.severity} /> }, { head: 'Status', cell: (c: any) => <Badge value={c.status} /> }]} />
          <Link to="/cases" className="mt-1 inline-block text-sm text-indigo-300">All cases →</Link></div>
      </div>
    </Page>
  )
}
