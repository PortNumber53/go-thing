export async function fetchCSRFToken(): Promise<string> {
  const res = await fetch('/csrf', { credentials: 'include' })
  if (!res.ok) throw new Error(`Failed to get CSRF token (HTTP ${res.status})`)
  const data: unknown = await res.json().catch(() => null)
  if (
    typeof data === 'object' &&
    data !== null &&
    'token' in data &&
    typeof (data as { token: unknown }).token === 'string' &&
    (data as { token: string }).token
  ) {
    return (data as { token: string }).token
  }
  throw new Error('Invalid CSRF token received')
}
