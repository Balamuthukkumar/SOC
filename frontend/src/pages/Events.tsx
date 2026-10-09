import { useRef, useState } from 'react'
import { Upload } from 'lucide-react'
import { api, unwrap } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Pager, Spinner, Stat, Table, fmt } from '../components/ui'

export default function Events() {
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [ip, setIp] = useState('')
  const [srcType, setSrcType] = useState('suricata')
  const file = useRef<HTMLInputElement>(null)
  const { data, error, loading, reload } = useAsync(async () => {
    const [list, stats] = await Promise.all([api('/events/', { params: { page, size: 25, severity, source_ip: ip } }), api('/events/stats')])
    return { list, stats: unwrap<any>(stats) }
  }, [page, severity, ip])
  const act = useAction()
  const [notice, setNotice] = useState<string | null>(null)

  const upload = async (f: File) => {
    const fd = new FormData(); fd.append('file', f)
    const res = await act.run(async () => {
      const r = await fetch(`/api/v1/events/upload?source_type=${srcType}`, { method: 'POST', body: fd, credentials: 'include' })
      const j = await r.json(); if (!r.ok) throw new Error(j.detail ?? 'Upload failed'); return j
    })
    if (res) { setNotice(`Ingested ${res.data.accepted} events (${res.data.rejected} rejected).`); reload() }
  }

  return (
    <Page title="Security events" actions={<>
      <input className="input w-36" placeholder="Source IP" value={ip} onChange={(e) => { setIp(e.target.value); setPage(1) }} />
      <select className="input w-auto" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}>
        <option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s}>{s}</option>)}</select>
      <select className="input w-auto" value={srcType} onChange={(e) => setSrcType(e.target.value)}>{['suricata', 'zeek', 'generic'].map((s) => <option key={s}>{s}</option>)}</select>
      <button className="btn" onClick={() => file.current?.click()} disabled={act.busy}><Upload size={14} /> Upload</button>
      <input ref={file} type="file" hidden accept=".json,.log,.jsonl" onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
    </>}>
      <ErrorBox error={error ?? act.error} />
      {notice && <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm text-emerald-300">{notice}</div>}
      {loading && !data ? <Spinner /> : data && (<>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          <Stat label="Total" value={data.stats.total_events} />
          {['critical', 'high', 'medium', 'low'].map((s) => <Stat key={s} label={s} value={data.stats.by_severity[s]} />)}
        </div>
        <Table rows={data.list.events} empty="No real sensor events ingested yet" cols={[
          { head: 'Time', cell: (e: any) => fmt(e.timestamp) },
          { head: 'Sensor', cell: (e: any) => <span className="text-xs text-slate-400">{e.source_type ?? '—'}</span> },
          { head: 'Type', cell: (e: any) => e.event_type },
          { head: 'Severity', cell: (e: any) => <Badge value={e.severity} /> }, { head: 'Signature', cell: (e: any) => e.signature ?? e.domain ?? '—' },
          { head: 'Source IP', cell: (e: any) => <span className="font-mono text-xs">{e.source_ip ?? '—'}</span> },
          { head: 'Destination', cell: (e: any) => <span className="font-mono text-xs">{e.dest_ip ?? '—'}{e.dest_port ? `:${e.dest_port}` : ''}</span> },
          { head: 'Action', cell: (e: any) => e.action ?? '' },
        ]} />
        <Pager page={page} pages={Math.ceil(data.list.total / data.list.size)} onPage={setPage} />
      </>)}
    </Page>
  )
}
