import React from 'react'
import { marked } from 'marked'
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
  // Signup modal state
  const [showSignup, setShowSignup] = React.useState(false)
  const [suEmail, setSuEmail] = React.useState('')
  const [suName, setSuName] = React.useState('')
  const [suPass, setSuPass] = React.useState('')
  const [suSubmitting, setSuSubmitting] = React.useState(false)
  const [suMsg, setSuMsg] = React.useState<string | null>(null)
  // Login/session state
  const [showLogin, setShowLogin] = React.useState(false)
  const [liEmail, setLiEmail] = React.useState('')
  const [liPass, setLiPass] = React.useState('')
  const [liSubmitting, setLiSubmitting] = React.useState(false)
  const [liMsg, setLiMsg] = React.useState<string | null>(null)
  const [me, setMe] = React.useState<{ id: number; username: string; name: string } | null>(null)

  React.useEffect(() => {
    autoResize()
  }, [])

  React.useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight
    }
  }, [messages, sending])

  // Load session
  React.useEffect(() => {
    ;(async () => {
      try {
        const res = await fetch('/me')
        if (!res.ok) return
        const data = await res.json()
        if (data && typeof data.id === 'number') setMe({ id: data.id, username: data.username, name: data.name })
      } catch (_) {
        /* ignore */
      }
    })()
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

  async function login() {
    const email = liEmail.trim()
    const pass = liPass
    setLiMsg(null)
    if (!email || !pass) {
      setLiMsg('Please enter email and password.')
      return
    }
    setLiSubmitting(true)
    try {
      const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email, password: pass }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setLiMsg(typeof data.error === 'string' ? data.error : `Login failed (HTTP ${res.status})`)
        return
      }
      setMe(data.user)
      setLiMsg('Logged in!')
      setLiEmail('')
      setLiPass('')
      setTimeout(() => setShowLogin(false), 500)
    } catch (e: any) {
      setLiMsg(`Login failed: ${e?.message ?? e}`)
    } finally {
      setLiSubmitting(false)
    }
  }

  async function logout() {
    try {
      await fetch('/logout', { method: 'POST' })
    } catch (_) {
      // ignore
    } finally {
      setMe(null)
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  async function signup() {
    const email = suEmail.trim()
    const name = suName.trim()
    const pass = suPass
    setSuMsg(null)
    if (!email || !name || !pass) {
      setSuMsg('Please fill in all fields.')
      return
    }
    setSuSubmitting(true)
    try {
      const res = await fetch('/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email, name, password: pass }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setSuMsg(typeof data.error === 'string' ? data.error : `Signup failed (HTTP ${res.status})`)
        return
      }
      setSuMsg('Account created! You can now log in.')
      // simple reset
      setSuEmail('')
      setSuName('')
      setSuPass('')
      // Close modal after short delay
      setTimeout(() => setShowSignup(false), 900)
    } catch (e: any) {
      setSuMsg(`Signup failed: ${e?.message ?? e}`)
    } finally {
      setSuSubmitting(false)
    }
  }

  return (
    <div className="chat-container">
      <header>
        <div className="nav">
          <div className="brand">AI Agent Chat</div>
          <nav className="actions">
            {me ? (
              <>
                <span className="user">Hello, {me.name}</span>
                <button className="link" type="button" onClick={logout}>Log Out</button>
              </>
            ) : (
              <>
                <button className="link" type="button" onClick={() => setShowSignup(true)}>Sign Up</button>
                <button className="link" type="button" onClick={() => setShowLogin(true)}>Log In</button>
              </>
            )}
          </nav>
        </div>
      </header>
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

      {showSignup && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Sign up">
          <div className="modal">
            <div className="modal-header">
              <div className="modal-title">Create your account</div>
              <button className="icon" onClick={() => setShowSignup(false)} aria-label="Close">×</button>
            </div>
            <div className="modal-body">
              <label>
                Email
                <input type="email" value={suEmail} onChange={(e) => setSuEmail(e.target.value)} placeholder="you@example.com" />
              </label>
              <label>
                Name
                <input type="text" value={suName} onChange={(e) => setSuName(e.target.value)} placeholder="Your name" />
              </label>
              <label>
                Password
                <input type="password" value={suPass} onChange={(e) => setSuPass(e.target.value)} placeholder="••••••••" />
              </label>
              {suMsg && <div className="system-msg" style={{ marginTop: 8 }}>{suMsg}</div>}
            </div>
            <div className="modal-footer">
              <button className="btn" onClick={signup} disabled={suSubmitting}>Create account</button>
            </div>
          </div>
        </div>
      )}

      {showLogin && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Log in">
          <div className="modal">
            <div className="modal-header">
              <div className="modal-title">Log in</div>
              <button className="icon" onClick={() => setShowLogin(false)} aria-label="Close">×</button>
            </div>
            <div className="modal-body">
              <label>
                Email
                <input type="email" value={liEmail} onChange={(e) => setLiEmail(e.target.value)} placeholder="you@example.com" />
              </label>
              <label>
                Password
                <input type="password" value={liPass} onChange={(e) => setLiPass(e.target.value)} placeholder="••••••••" />
              </label>
              {liMsg && <div className="system-msg" style={{ marginTop: 8 }}>{liMsg}</div>}
            </div>
            <div className="modal-footer">
              <button className="btn" onClick={login} disabled={liSubmitting}>Log in</button>
            </div>
          </div>
        </div>
      )}
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
