import { useState } from 'react'
import { useAuth } from '../auth'
import { api, unwrap } from '../api'
import { useAction, useAsync } from '../hooks'
import { Badge, ErrorBox, Page, Table, fmt } from '../components/ui'

export default function SettingsPage() {
  const { user } = useAuth()
  const [slack, setSlack] = useState('')
  const [hook, setHook] = useState('')
  const [mfa, setMfa] = useState<{ secret: string; provisioning_uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [orgForm, setOrgForm] = useState({ name: '', slug: '' })
  const [integ, setInteg] = useState({ integration_type: 'pagerduty', name: '', config: '{\n  "routing_key": ""\n}' })
  const act = useAction()
  const org = useAsync(() => api('/orgs/me').catch(() => null))
  const usage = useAsync(() => api('/billing/usage').then((r) => unwrap<any>(r)).catch(() => null))
  const integrations = useAsync(async () => unwrap<any[]>(await api('/integrations/')))
  const audit = useAsync(() => api<any[]>('/auth/audit-logs', { params: { limit: 20 } }))

  const done = (m: string) => setMsg(m)
  return (
    <Page title="Settings">
      <ErrorBox error={act.error} />
      {msg && <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm text-emerald-300">{msg}</div>}

      <section className="card space-y-2"><h2 className="font-semibold">Account</h2>
        <div className="text-sm text-slate-400">{user?.email} · {user?.role} · MFA {user?.mfa_enabled ? 'on' : 'off'}</div>
        <div className="grid gap-2 sm:grid-cols-2"><input className="input" placeholder="Slack webhook URL (https)" value={slack} onChange={(e) => setSlack(e.target.value)} /><input className="input" placeholder="Generic webhook URL (https)" value={hook} onChange={(e) => setHook(e.target.value)} /></div>
        <button className="btn" disabled={act.busy} onClick={async () => { if (await act.run(() => api('/auth/me/integrations', { method: 'PATCH', body: { slack_webhook_url: slack || null, webhook_url: hook || null } }))) done('Notification webhooks saved.') }}>Save webhooks</button>
      </section>

      <section className="card space-y-2"><h2 className="font-semibold">Two-factor authentication</h2>
        {!mfa ? <button className="btn-ghost" onClick={async () => { const r = await act.run(() => api('/auth/me/mfa/setup', { method: 'POST' })); if (r) setMfa(r) }}>Set up authenticator app</button> : <>
          <p className="text-sm text-slate-300">Add this secret to your authenticator app, then enter a code to confirm.</p>
          <code className="block break-all rounded bg-slate-800 p-2 text-xs">{mfa.secret}</code>
          <div className="flex gap-2"><input className="input w-40" placeholder="123456" value={code} onChange={(e) => setCode(e.target.value)} />
            <button className="btn" onClick={async () => { const ok = await act.run(() => api('/auth/me/mfa/verify', { body: { code } })); done(ok ? 'MFA enabled. Send the code in an X-MFA-Code header when signing in via API.' : 'Code was not valid.') }}>Verify</button></div></>}
      </section>

      <section className="card space-y-2"><h2 className="font-semibold">Organization & plan</h2>
        {org.data ? <div className="text-sm text-slate-300">{org.data.name} · <Badge value={org.data.plan} />{usage.data && <> · assets {usage.data.assets.current}/{usage.data.assets.limit} · users {usage.data.users.current}/{usage.data.users.limit}</>}</div> : <div className="flex flex-wrap gap-2">
          <input className="input w-48" placeholder="Organization name" value={orgForm.name} onChange={(e) => setOrgForm({ ...orgForm, name: e.target.value })} />
          <input className="input w-48" placeholder="slug (lowercase-hyphens)" value={orgForm.slug} onChange={(e) => setOrgForm({ ...orgForm, slug: e.target.value })} />
          <button className="btn" disabled={act.busy} onClick={async () => { if (await act.run(() => api('/orgs/', { body: orgForm }))) { org.reload(); usage.reload(); done('Organization created.') } }}>Create</button></div>}
      </section>

      <section className="space-y-2"><h2 className="font-semibold">Integrations</h2>
        <Table rows={integrations.data ?? []} empty="No integrations configured." cols={[{ head: 'Name', cell: (i: any) => i.name }, { head: 'Type', cell: (i: any) => i.integration_type }, { head: 'Active', cell: (i: any) => (i.is_active ? 'yes' : 'no') },
          { head: '', cell: (i: any) => <div className="flex gap-2"><button className="btn-ghost" onClick={async () => { const r = await act.run(() => api(`/integrations/${i.id}/test`, { method: 'POST' })); if (r) done(`${i.name}: ${JSON.stringify(unwrap(r))}`) }}>Test</button>
            <button className="btn-ghost" onClick={async () => { await act.run(() => api(`/integrations/${i.id}`, { method: 'DELETE' })); integrations.reload() }}>Delete</button></div> }]} />
        <div className="card grid gap-2 sm:grid-cols-2">
          <select className="input" value={integ.integration_type} onChange={(e) => setInteg({ ...integ, integration_type: e.target.value })}>{['splunk', 'sentinel', 'servicenow', 'pagerduty'].map((t) => <option key={t}>{t}</option>)}</select>
          <input className="input" placeholder="Name" value={integ.name} onChange={(e) => setInteg({ ...integ, name: e.target.value })} />
          <textarea className="input font-mono sm:col-span-2" rows={4} value={integ.config} onChange={(e) => setInteg({ ...integ, config: e.target.value })} />
          <button className="btn w-fit" disabled={act.busy} onClick={async () => {
            let config: any; try { config = JSON.parse(integ.config) } catch { act.setError('Config must be valid JSON'); return }
            if (await act.run(() => api('/integrations/', { body: { ...integ, config } }))) { integrations.reload(); done('Integration saved. Secrets are encrypted and masked.') } }}>Add integration</button></div>
      </section>

      <section className="space-y-2"><h2 className="font-semibold">Audit log</h2>
        <Table rows={audit.data ?? []} empty="No entries." cols={[{ head: 'When', cell: (a: any) => fmt(a.created_at) }, { head: 'Action', cell: (a: any) => a.action }, { head: 'IP', cell: (a: any) => a.ip_address ?? '' }]} /></section>
    </Page>
  )
}
