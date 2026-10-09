import { useState, type FormEvent } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import { api } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Pager, Spinner, Table } from '../components/ui'

const ZONES = ['unknown', 'it', 'dmz', 'supervisory', 'control', 'field', 'safety_system']
const BLANK = { name: '', asset_type: 'plc', vendor: '', product: '', version: '', network_zone: 'unknown', criticality: 'medium', is_ot_asset: false, last_known_ip: '', primary_protocol: '' }

export default function Assets() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [form, setForm] = useState<typeof BLANK | null>(null)
  const types = useAsync(() => api<string[]>('/assets/types/'))
  const { data, error, loading, reload } = useAsync(() => api('/assets/', { params: { page, size: 15, search } }), [page, search])
  const act = useAction()

  const save = async (e: FormEvent) => {
    e.preventDefault()
    const body = Object.fromEntries(Object.entries(form!).map(([k, v]) => [k, v === '' ? null : v]))
    const ok = await act.run(() => api('/assets/', { body }))
    if (ok) { setForm(null); reload() }
  }
  const remove = async (id: number) => { if (confirm('Delete this asset and its alerts?')) { await act.run(() => api(`/assets/${id}`, { method: 'DELETE' })); reload() } }
  const set = (k: string, v: any) => setForm((f) => ({ ...f!, [k]: v }))

  return (
    <Page title="Assets" actions={<>
      <input className="input w-48" placeholder="Search name…" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1) }} />
      <button className="btn" onClick={() => setForm(BLANK)}><Plus size={14} /> Add asset</button>
    </>}>
      <ErrorBox error={error ?? act.error} />
      {form && (
        <form onSubmit={save} className="card grid gap-2 sm:grid-cols-3">
          <input className="input sm:col-span-2" placeholder="Name *" required value={form.name} onChange={(e) => set('name', e.target.value)} />
          <select className="input" value={form.asset_type} onChange={(e) => set('asset_type', e.target.value)}>{(types.data ?? [form.asset_type]).map((t) => <option key={t}>{t}</option>)}</select>
          <input className="input" placeholder="Vendor" value={form.vendor} onChange={(e) => set('vendor', e.target.value)} />
          <input className="input" placeholder="Product" value={form.product} onChange={(e) => set('product', e.target.value)} />
          <input className="input" placeholder="Version" value={form.version} onChange={(e) => set('version', e.target.value)} />
          <select className="input" value={form.network_zone} onChange={(e) => set('network_zone', e.target.value)}>{ZONES.map((z) => <option key={z}>{z}</option>)}</select>
          <select className="input" value={form.criticality} onChange={(e) => set('criticality', e.target.value)}>{['low', 'medium', 'high', 'critical'].map((z) => <option key={z}>{z}</option>)}</select>
          <input className="input" placeholder="IP address" value={form.last_known_ip} onChange={(e) => set('last_known_ip', e.target.value)} />
          <input className="input" placeholder="Protocol (modbus, dnp3…)" value={form.primary_protocol} onChange={(e) => set('primary_protocol', e.target.value)} />
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.is_ot_asset} onChange={(e) => set('is_ot_asset', e.target.checked)} /> OT asset</label>
          <div className="flex gap-2 sm:col-span-2 sm:justify-end"><button type="button" className="btn-ghost" onClick={() => setForm(null)}>Cancel</button><button className="btn" disabled={act.busy}>Save</button></div>
        </form>
      )}
      {loading && !data ? <Spinner /> : data && (<>
        <Table rows={data.assets} cols={[
          { head: 'Name', cell: (a: any) => a.name }, { head: 'Type', cell: (a: any) => a.asset_type },
          { head: 'Vendor / product', cell: (a: any) => [a.vendor, a.product, a.version].filter(Boolean).join(' ') || '—' },
          { head: 'Zone', cell: (a: any) => a.network_zone }, { head: 'IP', cell: (a: any) => <span className="font-mono text-xs">{a.last_known_ip ?? '—'}</span> },
          { head: 'Criticality', cell: (a: any) => <Badge value={a.criticality} /> }, { head: 'OT', cell: (a: any) => (a.is_ot_asset ? 'yes' : '') },
          { head: '', cell: (a: any) => <button className="text-slate-500 hover:text-red-400" onClick={() => remove(a.id)}><Trash2 size={14} /></button> },
        ]} />
        <Pager page={page} pages={Math.ceil(data.total / data.size)} onPage={setPage} />
      </>)}
    </Page>
  )
}
