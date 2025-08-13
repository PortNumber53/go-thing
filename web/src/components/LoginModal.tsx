import React from 'react'
import { User, LoginSuccess, isLoginSuccess } from '../types'
 type LoginError = { error?: string }
 
interface LoginModalProps {
  open: boolean
  onClose: () => void
  onSuccess: (user: User) => void
}

export default function LoginModal({ open, onClose, onSuccess }: LoginModalProps) {
  const [email, setEmail] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [submitting, setSubmitting] = React.useState(false)
  const [msg, setMsg] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (!open) {
      setEmail('')
      setPassword('')
      setMsg(null)
      setSubmitting(false)
    }
  }, [open])

  async function login() {
    const e = email.trim()
    const p = password
    setMsg(null)
    if (!e || !p) {
      setMsg('Please enter email and password.')
      return
    }
    setSubmitting(true)
    try {
      const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: e, password: p }),
      })
      const data: unknown = await res.json()
      if (!res.ok) {
        setMsg((data as LoginError).error ?? `Login failed (HTTP ${res.status})`)
        return
      }
      if (isLoginSuccess(data)) {
        onSuccess(data.user)
        setMsg('Logged in!')
        setTimeout(() => onClose(), 500)
      } else {
        setMsg('Login failed: Invalid response from server.')
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)
      setMsg(`Login failed: ${message}`)
    } finally {
      setSubmitting(false)
    }
  }

  if (!open) return null

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Log in">
      <div className="modal">
        <div className="modal-header">
          <div className="modal-title">Log in</div>
          <button className="icon" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          <label>
            Email
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
          </label>
          {msg && <div className="system-msg" style={{ marginTop: 8 }}>{msg}</div>}
        </div>
        <div className="modal-footer">
          <button className="btn" onClick={login} disabled={submitting}>Log in</button>
        </div>
      </div>
    </div>
  )
}
