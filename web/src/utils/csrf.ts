export async function fetchCSRFToken(): Promise<string> {
  const res = await fetch('/csrf', { credentials: 'include' })
  if (!res.ok) throw new Error(`Failed to get CSRF token (HTTP ${res.status})`)
  const data = await res.json().catch(() => null)
  const token = (data as any)?.token
  if (typeof token !== 'string' || !token) {
    throw new Error('Invalid CSRF token received')
  }
  return token
}
