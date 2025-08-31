import React from 'react'
import { marked } from 'marked'
import { fetchCSRFToken } from './utils/csrf'
import LoginModal from './components/LoginModal'
import SignupModal from './components/SignupModal'
import { User, isUser } from './types'
import useOutsideDismiss from './hooks/useOutsideDismiss'
// Ensure marked.parse returns string (not Promise<string>)
marked.setOptions({ async: false })

type Who = 'You' | 'Agent' | 'System'
type Msg = { id: string; who: Who; text: string }

export default function App() {
  const [messages, setMessages] = React.useState<Msg[]>([])
  const [input, setInput] = React.useState('')
  const [sending, setSending] = React.useState(false)
  const chatRef = React.useRef<HTMLDivElement | null>(null)
  const taRef = React.useRef<HTMLTextAreaElement | null>(null)
  // Signup/Login modal visibility
  const [showSignup, setShowSignup] = React.useState(false)
  const [showLogin, setShowLogin] = React.useState(false)
  const [me, setMe] = React.useState<User | null>(null)
  // Account dropdown menu state
  const [showAccountMenu, setShowAccountMenu] = React.useState(false)
  const accountBtnRef = React.useRef<HTMLButtonElement | null>(null)
  const accountMenuRef = React.useRef<HTMLDivElement | null>(null)
  // Simple hash routing: '/' (chat) or '/settings'
  const [route, setRoute] = React.useState<string>(() => window.location.hash.replace(/^#/, '') || '/')

  React.useEffect(() => {
    autoResize()
  }, [])

  // Track hash-based route changes
  React.useEffect(() => {
    const onHash = () => setRoute(window.location.hash.replace(/^#/, '') || '/')
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  // Close Account menu on outside click or Escape via reusable hook
  useOutsideDismiss(
    [
      accountBtnRef as unknown as React.RefObject<HTMLElement | null>,
      accountMenuRef as unknown as React.RefObject<HTMLElement | null>,
    ],
    () => setShowAccountMenu(false),
    { enabled: showAccountMenu, restoreFocusTo: accountBtnRef as unknown as React.RefObject<HTMLElement | null> }
  )

  React.useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight
    }
  }, [messages, sending])

  // Load session
  React.useEffect(() => {
    const controller = new AbortController()
    ;(async () => {
      try {
        const res = await fetch('/me', { signal: controller.signal })
        if (!res.ok) return
        const data: unknown = await res.json()
        if (isUser(data)) {
          setMe(data)
        }
      } catch (_) {
        /* ignore, including abort */
      }
    })()
    return () => controller.abort()
  }, [])

  function autoResize() {
    const el = taRef.current
    if (!el) return
    el.style.height = 'auto'
    const max = Math.floor(window.innerHeight * 0.35)
    el.style.height = Math.min(el.scrollHeight, max) + 'px'
  }

  function append(text: string, who: Who) {
    setMessages((m) => [...m, { id: crypto.randomUUID(), who, text }])
  }

  async function send() {
    const msg = input.trim()
    if (!msg || sending) return
    append(msg, 'You')
    setInput('')
    setSending(true)
    const thinking: Msg = { id: crypto.randomUUID(), who: 'System', text: 'Thinking…' }
    setMessages((m) => [...m, thinking])

    try {
      const res = await fetch('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setMessages((m) => m.filter((x) => x.id !== thinking.id))
      if (data && typeof data.response === 'string') {
        append(data.response, 'Agent')
      } else {
        append('Error: Invalid or missing response from server.', 'System')
      }
    } catch (e: any) {
      setMessages((m) => m.filter((x) => x.id !== thinking.id))
      append(`Error: Failed to communicate with server. ${e?.message ?? e}`, 'System')
    } finally {
      setSending(false)
      autoResize()
    }
  }

  // login handled in LoginModal; on success we setMe and close modal

  async function logout() {
    try {
      // Fetch CSRF token first (validated)
      const token = await fetchCSRFToken()

      await fetch('/logout', {
        method: 'POST',
        headers: {
          'X-CSRF-Token': token,
        },
        credentials: 'include', // ensure cookies (incl. csrf_token) are sent
      })
    } catch (err) {
      console.error('Logout failed:', err)
      // Optionally show a toast; silent failure can be acceptable for logout
    } finally {
      setMe(null)
    }
  }

  function navigate(path: string) {
    const p = path.startsWith('/') ? path : '/' + path
    window.location.hash = p
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  // signup handled in SignupModal; on success we may show a toast or just close

  return (
    <div className="chat-container">
      <header>
        <div className="nav">
          <div className="brand">AI Agent Chat</div>
          <nav className="actions">
            {me ? (
              <div className="account">
                <button
                  ref={accountBtnRef}
                  className="account-btn link"
                  type="button"
                  aria-haspopup="menu"
                  aria-expanded={showAccountMenu}
                  onClick={() => setShowAccountMenu(v => !v)}
                >
                  <span className="user">{me.name}</span>
                  <span aria-hidden>▾</span>
                </button>
                {showAccountMenu && (
                  <div
                    ref={accountMenuRef}
                    role="menu"
                    className="account-menu"
                  >
                    <div className="menu-section">Account</div>
                    {/* Settings page (frontend-rendered at #/settings) */}
                    <button
                      role="menuitem"
                      className="menu-item"
                      onClick={() => {
                        setShowAccountMenu(false)
                        navigate('/settings')
                      }}
                    >
                      Settings
                    </button>
                    <button role="menuitem" className="menu-item" onClick={() => { setShowAccountMenu(false); logout(); }}>Log out</button>
                  </div>
                )}
              </div>
            ) : (
              <>
                <button className="link" type="button" onClick={() => setShowSignup(true)}>Sign Up</button>
                <button className="link" type="button" onClick={() => setShowLogin(true)}>Log In</button>
              </>
            )}
          </nav>
        </div>
      </header>
      {route === '/settings' ? (
        <SettingsPage me={me} onNameUpdated={(newName) => setMe(me => me ? { ...me, name: newName } : me)} />
      ) : (
        <>
          <main id="chat" ref={chatRef} aria-live="polite" aria-atomic="false">
            <div className="chat-inner">
              {messages.map((m) => (
                <div key={m.id} className={`bubble ${m.who === 'Agent' ? 'agent-msg' : m.who === 'You' ? 'user-msg' : 'system-msg'}`}>
                  {m.who === 'Agent' ? (
                    <div dangerouslySetInnerHTML={{ __html: safeMarked(m.text) }} />
                  ) : (
                    m.text
                  )}
                </div>
              ))}
            </div>
          </main>
          <div className="composer">
            <div className="row">
              <textarea
                id="input"
                ref={taRef}
                value={input}
                onChange={(e) => {
                  setInput(e.target.value)
                  autoResize()
                }}
                onKeyDown={onKeyDown}
                placeholder="Type a message..."
                rows={1}
                aria-label="Message input"
              />
              <button id="sendBtn" type="button" onClick={send} disabled={sending} aria-label="Send message">
                Send
              </button>
            </div>
            <div className="system-msg" id="hint">
              Press Enter to send, Shift+Enter for new line
            </div>
          </div>
        </>
      )}

      <SignupModal open={showSignup} onClose={() => setShowSignup(false)} />

      <LoginModal open={showLogin} onClose={() => setShowLogin(false)} onSuccess={setMe} />
    </div>
  )
}

function safeMarked(s: string): string {
  try {
    if (typeof s !== 'string') return 'No or invalid response from server.'
    return marked.parse(s) as string
  } catch (e: any) {
    return `Error rendering response: ${e?.message ?? e}`
  }
}

type SettingsProps = { me: User | null, onNameUpdated: (newName: string) => void }

function SettingsPage({ me, onNameUpdated }: SettingsProps) {
  const [username, setUsername] = React.useState('')
  const [name, setName] = React.useState('')
  const [loading, setLoading] = React.useState(true)
  const [saving, setSaving] = React.useState(false)
  const [message, setMessage] = React.useState<string | null>(null)
  // Tabs: profile | password | docker
  const [tab, setTab] = React.useState<'profile' | 'password' | 'docker'>('profile')

  const [curPass, setCurPass] = React.useState('')
  const [newPass, setNewPass] = React.useState('')
  const [confirmPass, setConfirmPass] = React.useState('')
  const [changing, setChanging] = React.useState(false)

  // SSH Key Generation state
  const [keyType, setKeyType] = React.useState<'ed25519' | 'rsa'>('ed25519')
  const [rsaBits, setRsaBits] = React.useState<number>(3072)
  const [keyComment, setKeyComment] = React.useState('')
  const [keyPass, setKeyPass] = React.useState('')
  const [genLoading, setGenLoading] = React.useState(false)
  const [pubKey, setPubKey] = React.useState<string>('')
  const [privKey, setPrivKey] = React.useState<string>('')
  const [showPriv, setShowPriv] = React.useState(false)

  React.useEffect(() => {
    let aborted = false
    ;(async () => {
      try {
        const res = await fetch('/api/settings')
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        if (!aborted) {
          setUsername(data.username ?? '')
          setName(data.name ?? '')
        }
      } catch (e: any) {
        if (!aborted) setMessage(`Failed to load settings: ${e?.message ?? e}`)
      } finally {
        if (!aborted) setLoading(false)
      }
    })()
    return () => { aborted = true }
  }, [])

  async function saveProfile(e: React.FormEvent) {
    e.preventDefault()
    setMessage(null)
    const trimmed = name.trim()
    if (!trimmed) { setMessage('Name is required'); return }
    setSaving(true)
    try {
      const token = await fetchCSRFToken()
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ name: trimmed }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      onNameUpdated(trimmed)
      setMessage('Profile updated')
    } catch (e: any) {
      setMessage(`Failed to update: ${e?.message ?? e}`)
    } finally {
      setSaving(false)
    }
  }

  async function changePassword(e: React.FormEvent) {
    e.preventDefault()
    setMessage(null)
    if (newPass.length < 8) { setMessage('New password must be at least 8 characters'); return }
    if (newPass !== confirmPass) { setMessage('New password and confirmation do not match'); return }
    setChanging(true)
    try {
      const token = await fetchCSRFToken()
      const res = await fetch('/api/settings/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ current_password: curPass, new_password: newPass }),
      })
      if (!res.ok) {
        const t = await res.text()
        throw new Error(t || `HTTP ${res.status}`)
      }
      setMessage('Password changed successfully')
      setCurPass(''); setNewPass(''); setConfirmPass('')
    } catch (e: any) {
      setMessage(`Failed to change password: ${e?.message ?? e}`)
    } finally {
      setChanging(false)
    }
  }

  async function generateKeys(e: React.FormEvent) {
    e.preventDefault()
    setMessage(null)
    setGenLoading(true)
    setPubKey(''); setPrivKey('')
    try {
      const token = await fetchCSRFToken()
      const payload: any = {
        type: keyType,
        comment: keyComment.trim(),
        passphrase: keyPass,
      }
      if (keyType === 'rsa') payload.bits = rsaBits
      const res = await fetch('/api/ssh-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify(payload),
      })
      if (!res.ok) {
        const t = await res.text()
        throw new Error(t || `HTTP ${res.status}`)
      }
      const data = await res.json()
      if (typeof data?.public_key === 'string' && typeof data?.private_key === 'string') {
        setPubKey(data.public_key.trim())
        setPrivKey(data.private_key.trim())
      } else {
        throw new Error('Malformed response from server')
      }
    } catch (e: any) {
      setMessage(`Failed to generate keys: ${e?.message ?? e}`)
    } finally {
      setGenLoading(false)
    }
  }

  function download(text: string, filename: string) {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <main className="settings" aria-live="polite" aria-atomic="false" style={{ maxWidth: 720, margin: '0 auto', padding: '1rem' }}>
      <h1>User Settings</h1>
      {loading ? (
        <div>Loading…</div>
      ) : (
        <>
          {message && <div className="system-msg" role="status" style={{ marginBottom: '1rem' }}>{message}</div>}
          {/* Tabs */}
          <div className="row" role="tablist" aria-label="Settings Sections" style={{ gap: '0.5rem', marginBottom: '1rem' }}>
            <button role="tab" aria-selected={tab === 'profile'} className={tab === 'profile' ? 'link active' : 'link'} onClick={() => setTab('profile')}>Profile</button>
            <button role="tab" aria-selected={tab === 'password'} className={tab === 'password' ? 'link active' : 'link'} onClick={() => setTab('password')}>Password</button>
            <button role="tab" aria-selected={tab === 'docker'} className={tab === 'docker' ? 'link active' : 'link'} onClick={() => setTab('docker')}>Docker Settings</button>
          </div>

          {tab === 'profile' && (
            <section style={{ marginBottom: '2rem' }}>
              <h2>Profile</h2>
              <form onSubmit={saveProfile}>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'baseline' }}>
                  <label style={{ minWidth: 100 }}>Username</label>
                  <input type="text" value={username} disabled aria-readonly />
                </div>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'baseline', marginTop: '0.5rem' }}>
                  <label style={{ minWidth: 100 }}>Display name</label>
                  <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
                </div>
                <div style={{ marginTop: '0.75rem' }}>
                  <button type="submit" disabled={saving}>Save</button>
                </div>
              </form>
            </section>
          )}

          {tab === 'password' && (
            <section>
              <h2>Change Password</h2>
              <form onSubmit={changePassword}>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'baseline' }}>
                  <label style={{ minWidth: 160 }}>Current password</label>
                  <input type="password" value={curPass} onChange={(e) => setCurPass(e.target.value)} autoComplete="current-password" />
                </div>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'baseline', marginTop: '0.5rem' }}>
                  <label style={{ minWidth: 160 }}>New password</label>
                  <input type="password" value={newPass} onChange={(e) => setNewPass(e.target.value)} autoComplete="new-password" />
                </div>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'baseline', marginTop: '0.5rem' }}>
                  <label style={{ minWidth: 160 }}>Confirm new password</label>
                  <input type="password" value={confirmPass} onChange={(e) => setConfirmPass(e.target.value)} autoComplete="new-password" />
                </div>
                <div style={{ marginTop: '0.75rem' }}>
                  <button type="submit" disabled={changing}>Change password</button>
                </div>
              </form>
            </section>
          )}

          {tab === 'docker' && (
            <section>
              <h2>Docker Settings</h2>
              <p style={{ marginTop: '0.25rem', color: '#666' }}>Configure the built-in Docker sandbox used by shell tools. Saving is coming soon.</p>
              <form onSubmit={(e) => e.preventDefault()}>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'baseline', marginTop: '0.5rem' }}>
                  <label style={{ minWidth: 220 }}>Container name</label>
                  <input type="text" placeholder="go-thing-arch" disabled />
                </div>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'baseline', marginTop: '0.5rem' }}>
                  <label style={{ minWidth: 220 }}>Image</label>
                  <input type="text" placeholder="archlinux:latest" disabled />
                </div>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'baseline', marginTop: '0.5rem' }}>
                  <label style={{ minWidth: 220 }}>Extra args</label>
                  <input type="text" placeholder="--privileged" disabled />
                </div>
                <div className="row" style={{ gap: '0.5rem', alignItems: 'center', marginTop: '0.5rem' }}>
                  <label style={{ minWidth: 220 }}>Auto remove container on exit</label>
                  <input type="checkbox" disabled />
                </div>
                <div style={{ marginTop: '0.75rem' }}>
                  <button type="submit" disabled title="Coming soon">Save</button>
                </div>
              </form>
            </section>
          )}
        </>
      )}
    </main>
  )
}
