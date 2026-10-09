import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Spinner, Stat, Table, fmt } from '../components/ui'

export default function OTDiscovery() {
  const { data, error, loading, reload } = useAsync(async () => {
    const [summary, devices, protocols, zones, topo] = await Promise.all([
      api('/ot/summary'), api('/ot/discovered-devices', { params: { size: 50 } }), api('/ot/devices-by-protocol'), api('/ot/devices-by-zone'), api('/topology/stats')])
    return { summary, devices: devices.devices, protocols: protocols.protocols, zones: zones.zones, topo }
  })
  const act = useAction()
  const promote = async (id: number) => { await act.run(() => api(`/ot/discovered-devices/${id}/promote-to-asset`, { method: 'POST' })); reload() }
  if (loading && !data) return <Spinner />
  if (error || !data) return <ErrorBox error={error} />
  const { summary: s } = data
  const risk = (n: number) => (n >= 70 ? 'text-red-400' : n >= 40 ? 'text-yellow-300' : 'text-emerald-300')
  const chart = (rows: any[], key: string) => (
    <ResponsiveContainer width="100%" height={180}><BarChart data={rows}><XAxis dataKey={key} stroke="#64748b" fontSize={11} /><YAxis stroke="#64748b" allowDecimals={false} />
      <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} cursor={{ fill: '#1e293b' }} /><Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} isAnimationActive={false} /></BarChart></ResponsiveContainer>)

  return (
    <Page title="OT discovery">
      <ErrorBox error={act.error} />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Managed OT assets" value={s.managed_ot_assets} /><Stat label="Discovered OT devices" value={s.discovered_ot_devices} />
        <Stat label="Unmanaged OT devices" value={s.discovery_gap} tone={s.discovery_gap ? 'text-yellow-300' : 'text-emerald-300'} />
        <Stat label="High risk" value={s.high_risk_devices} tone="text-red-400" /><Stat label="Cleartext OT links" value={data.topo.unencrypted_ot_connections} tone="text-orange-300" />
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="card"><h2 className="mb-1 text-sm font-semibold text-slate-300">OT assets by Purdue zone</h2>{chart(data.zones, 'zone')}</div>
        <div className="card"><h2 className="mb-1 text-sm font-semibold text-slate-300">OT assets by protocol</h2>{chart(data.protocols, 'protocol')}</div>
      </div>
      <Table rows={data.devices} cols={[
        { head: 'IP', cell: (d: any) => <span className="font-mono text-xs">{d.ip_address}</span> }, { head: 'Host', cell: (d: any) => d.hostname ?? '—' },
        { head: 'Vendor / model', cell: (d: any) => [d.manufacturer, d.model].filter(Boolean).join(' ') || '—' }, { head: 'Type', cell: (d: any) => d.ot_device_type ?? (d.is_ot_device ? 'ot' : 'it') },
        { head: 'Risk', cell: (d: any) => <b className={risk(d.risk_score)}>{d.risk_score}</b> },
        { head: 'Factors', cell: (d: any) => <span className="text-xs text-slate-400">{(d.risk_factors ?? []).join(', ')}</span> },
        { head: 'Managed', cell: (d: any) => (d.is_correlated ? <Badge value="active" /> : <button className="btn-ghost" disabled={act.busy} onClick={() => promote(d.id)}>Promote to asset</button>) },
        { head: 'Last seen', cell: (d: any) => fmt(d.last_seen) },
      ]} />
    </Page>
  )
}
