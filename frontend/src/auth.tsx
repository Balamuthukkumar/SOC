import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, SESSION_EXPIRED } from './api'

export interface User { id: number; email: string; full_name: string | null; role: string; mfa_enabled: boolean }
interface Ctx { user: User | null; ready: boolean; login: (e: string, p: string) => Promise<void>; logout: () => Promise<void> }

const AuthContext = createContext<Ctx>(null!)
export const useAuth = () => useContext(AuthContext)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [ready, setReady] = useState(false)
  useEffect(() => {
    api<User>('/auth/me').then(setUser).catch(() => setUser(null)).finally(() => setReady(true))
    const expired = () => setUser(null)
    window.addEventListener(SESSION_EXPIRED, expired)
    return () => window.removeEventListener(SESSION_EXPIRED, expired)
  }, [])
  const login = async (email: string, password: string) => {
    await api('/auth/login', { form: { username: email, password } })
    setUser(await api<User>('/auth/me'))
  }
  const logout = async () => { await api('/auth/logout', { method: 'POST' }).catch(() => {}); setUser(null) }
  return <AuthContext.Provider value={{ user, ready, login, logout }}>{children}</AuthContext.Provider>
}
