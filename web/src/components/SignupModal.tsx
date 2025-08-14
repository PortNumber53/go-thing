import React from 'react'

 type SignupError = { error?: string }
 
interface SignupModalProps {
  open: boolean
  onClose: () => void
  onSuccess?: () => void
}

export default function SignupModal({ open, onClose, onSuccess }: SignupModalProps) {
  const [email, setEmail] = React.useState('')
  const [name, setName] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [submitting, setSubmitting] = React.useState(false)
  const [msg, setMsg] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (!open) {
      setEmail('')
      setName('')
      setPassword('')
      setMsg(null)
      setSubmitting(false)
    }
  }, [open])

  async function signup() {
    const e = email.trim()
    const n = name.trim()
    const p = password
    setMsg(null)
    if (!e || !n || !p) {
      setMsg('Please fill in all fields.')
      return
    }
    setSubmitting(true)
    try {
      // Fetch CSRF token first
      const csrfRes = await fetch('/csrf', { credentials: 'include' })
      if (!csrfRes.ok) {
        setMsg(`Signup failed: Could not get CSRF token (HTTP ${csrfRes.status})`)
        return
      }
      const { token: csrfToken } = await csrfRes.json() as { token?: string }
      if (!csrfToken) {
        setMsg('Signup failed: Invalid CSRF token received.')
        return
      }

      const res = await fetch('/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        credentials: 'include',
        body: JSON.stringify({ username: e, name: n, password: p }),
      })
      const data: unknown = await res.json()
      if (!res.ok) {
        setMsg((data as SignupError).error ?? `Signup failed (HTTP ${res.status})`)
        return
      }
      setMsg('Account created! You can now log in.')
      onSuccess?.()
      setTimeout(() => onClose(), 900)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)
      setMsg(`Signup failed: ${message}`)
    } finally {
      setSubmitting(false)
    }
  }

  if (!open) return null

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Sign up">
      <div className="modal">
        <div className="modal-header">
          <div className="modal-title">Sign up</div>
          <button className="icon" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <label>
            Email
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
          </label>
          <label>
            Name
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Ada Lovelace" />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
          </label>
          {msg && <div className="system-msg" style={{ marginTop: 8 }}>{msg}</div>}
        </div>
        <div className="modal-footer">
          <button className="btn" onClick={signup} disabled={submitting}>Sign up</button>
        </div>
      </div>
    </div>
  )
}
