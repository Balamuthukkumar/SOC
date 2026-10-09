import { useCallback, useEffect, useRef, useState } from 'react'

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const fnRef = useRef(fn)
  fnRef.current = fn
  const reload = useCallback(async () => {
    setLoading(true)
    try { setData(await fnRef.current()); setError(null) }
    catch (e: any) { setError(e.message ?? 'Request failed') }
    finally { setLoading(false) }
  }, [])
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { reload() }, deps)
  return { data, error, loading, reload }
}

export function useAction() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const run = async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true); setError(null)
    try { return await fn() } catch (e: any) { setError(e.message ?? 'Failed'); return undefined } finally { setBusy(false) }
  }
  return { busy, error, run, setError }
}
