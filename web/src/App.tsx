import React from 'react'
import { marked } from 'marked'

type Who = 'You' | 'Agent' | 'System'
type Msg = { id: string; who: Who; text: string }

export default function App() {
  const [messages, setMessages] = React.useState<Msg[]>([])
  const [input, setInput] = React.useState('')
  const [sending, setSending] = React.useState(false)
  const chatRef = React.useRef<HTMLDivElement | null>(null)
  const taRef = React.useRef<HTMLTextAreaElement | null>(null)

  React.useEffect(() => {
    autoResize()
  }, [])

  React.useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight
    }
  }, [messages, sending])

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

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  return (
    <div className="chat-container">
      <header>
        <h2>AI Agent Chat</h2>
      </header>
      <main id="chat" ref={chatRef} aria-live="polite" aria-atomic="false">
        {messages.map((m) => (
          <div key={m.id} className={`bubble ${m.who === 'Agent' ? 'agent-msg' : m.who === 'You' ? 'user-msg' : 'system-msg'}`}>
            {m.who === 'Agent' ? (
              <div dangerouslySetInnerHTML={{ __html: safeMarked(m.text) }} />
            ) : (
              m.text
            )}
          </div>
        ))}
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
    </div>
  )
}

function safeMarked(s: string): string {
  try {
    if (typeof s !== 'string') return 'No or invalid response from server.'
    return marked.parse(s)
  } catch (e: any) {
    return `Error rendering response: ${e?.message ?? e}`
  }
}
