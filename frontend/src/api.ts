export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

function messageFrom(body: any, fallback: string): string {
  const d = body?.detail ?? body?.error?.message
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map((e) => e.msg).join('; ')
  return fallback
}

export const SESSION_EXPIRED = 'soc:session-expired'

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; form?: Record<string, string>; params?: Record<string, any> } = {}): Promise<T> {
  const url = new URL('/api/v1' + path, window.location.origin)
  for (const [k, v] of Object.entries(opts.params ?? {})) if (v !== undefined && v !== '' && v !== null) url.searchParams.set(k, String(v))
  const headers: Record<string, string> = {}
  let body: BodyInit | undefined
  if (opts.form) { body = new URLSearchParams(opts.form); headers['Content-Type'] = 'application/x-www-form-urlencoded' }
  else if (opts.body !== undefined) { body = JSON.stringify(opts.body); headers['Content-Type'] = 'application/json' }
  const res = await fetch(url, { method: opts.method ?? (body ? 'POST' : 'GET'), headers, body, credentials: 'include' })
  if (res.status === 204) return undefined as T
  const data = await res.json().catch(() => null)
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/auth/login')) window.dispatchEvent(new Event(SESSION_EXPIRED))
    throw new ApiError(res.status, messageFrom(data, res.statusText))
  }
  return data as T
}

/** Unwraps the `{success, data}` envelope some endpoints use. */
export const unwrap = <T,>(r: any): T => (r && typeof r === 'object' && 'data' in r && 'success' in r ? r.data : r)
