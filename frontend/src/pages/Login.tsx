import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { useAuth } from '../auth'
import { api } from '../api'
import { ErrorBox } from '../components/ui'
import { useAction } from '../hooks'

export default function Login() {
  const { user, login } = useAuth()
  const nav = useNavigate()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('admin@example.com')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const { busy, error, run } = useAction()
  if (user) return <Navigate to="/" replace />

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    await run(async () => {
      if (mode === 'register') await api('/auth/register', { body: { email, password, full_name: name || null } })
      await login(email, password)
      nav('/')
    })
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="card w-full max-w-sm space-y-3">
        <div className="flex items-center gap-2 text-xl font-semibold text-white"><ShieldCheck className="text-indigo-400" /> SOC Platform</div>
        <ErrorBox error={error} />
        {mode === 'register' && <input className="input" placeholder="Full name" value={name} onChange={(e) => setName(e.target.value)} />}
        <input className="input" type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <input className="input" type="password" placeholder="Password (min 8 characters)" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <button className="btn w-full justify-center" disabled={busy}>{mode === 'login' ? 'Sign in' : 'Create account'}</button>
        <button type="button" className="w-full text-center text-sm text-slate-400 hover:text-slate-200" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>
          {mode === 'login' ? 'Need an account? Register' : 'Have an account? Sign in'}
        </button>
        <a className="block text-center text-sm text-slate-500 hover:text-slate-300" href="/api/v1/auth/github/login">Sign in with GitHub</a>
      </form>
    </div>
  )
}
