import React from "react";
// @ts-ignore - Provided by @xterm/xterm after install; local types stub exists
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { AttachAddon } from "@xterm/addon-attach";
import "@xterm/xterm/css/xterm.css";
import { marked } from "marked";
import { fetchCSRFToken } from "./utils/csrf";
import LoginModal from "./components/LoginModal";
import SignupModal from "./components/SignupModal";
import { User, isUser } from "./types";
import useOutsideDismiss from "./hooks/useOutsideDismiss";
// Ensure marked.parse returns string (not Promise<string>)
marked.setOptions({ async: false });

type Who = "You" | "Agent" | "System";
type Msg = { id: string; who: Who; text: string };

export default function App() {
  const [messages, setMessages] = React.useState<Msg[]>([]);
  const [input, setInput] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const chatRef = React.useRef<HTMLDivElement | null>(null);
  const taRef = React.useRef<HTMLTextAreaElement | null>(null);
  // Signup/Login modal visibility
  const [showSignup, setShowSignup] = React.useState(false);
  const [showLogin, setShowLogin] = React.useState(false);
  const [me, setMe] = React.useState<User | null>(null);
  // Account dropdown menu state
  const [showAccountMenu, setShowAccountMenu] = React.useState(false);
  const accountBtnRef = React.useRef<HTMLButtonElement | null>(null);
  const accountMenuRef = React.useRef<HTMLDivElement | null>(null);
  // Routing now uses pathname for page and path segment for settings tab
  const getRoute = () => window.location.pathname || "/";
  const getTabFromPath = (): "profile" | "password" | "docker" => {
    const p = (window.location.pathname || "/").toLowerCase();
    if (!p.startsWith("/account/settings")) return "profile";
    const parts = p.split("/").filter(Boolean); // e.g., ["account","settings","docker"]
    const maybe = parts[2] || "";
    if (maybe === "password") return "password";
    if (maybe === "docker") return "docker";
    return "profile";
  };

  const [route, setRoute] = React.useState<string>(() => getRoute());
  // Settings tab state lifted to App for a fixed toolbar under header
  const [settingsTab, setSettingsTab] = React.useState<
    "profile" | "password" | "docker"
  >(() => getTabFromPath());

  React.useEffect(() => {
    autoResize();
  }, []);

  // Track history changes
  React.useEffect(() => {
    const onPop = () => {
      setRoute(getRoute());
      setSettingsTab(getTabFromPath());
    };
    window.addEventListener("popstate", onPop);
    return () => {
      window.removeEventListener("popstate", onPop);
    };
  }, []);

  // Close Account menu on outside click or Escape via reusable hook
  useOutsideDismiss(
    [
      accountBtnRef as unknown as React.RefObject<HTMLElement | null>,
      accountMenuRef as unknown as React.RefObject<HTMLElement | null>,
    ],
    () => setShowAccountMenu(false),
    {
      enabled: showAccountMenu,
      restoreFocusTo:
        accountBtnRef as unknown as React.RefObject<HTMLElement | null>,
    }
  );

  React.useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight;
    }
  }, [messages, sending]);

  // Load session
  React.useEffect(() => {
    const controller = new AbortController();
    (async () => {
      try {
        const res = await fetch("/me", { signal: controller.signal });
        if (!res.ok) return;
        const data: unknown = await res.json();
        if (isUser(data)) {
          setMe(data);
        }
      } catch (_) {
        /* ignore, including abort */
      }
    })();
    return () => controller.abort();
  }, []);

  function autoResize() {
    const el = taRef.current;
    if (!el) return;
    el.style.height = "auto";
    const max = Math.floor(window.innerHeight * 0.35);
    el.style.height = Math.min(el.scrollHeight, max) + "px";
  }

  function append(text: string, who: Who) {
    setMessages((m) => [...m, { id: crypto.randomUUID(), who, text }]);
  }

  async function send() {
    const msg = input.trim();
    if (!msg || sending) return;
    append(msg, "You");
    setInput("");
    setSending(true);
    const thinking: Msg = {
      id: crypto.randomUUID(),
      who: "System",
      text: "Thinking…",
    };
    setMessages((m) => [...m, thinking]);

    try {
      const res = await fetch("/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setMessages((m) => m.filter((x) => x.id !== thinking.id));
      if (data && typeof data.response === "string") {
        append(data.response, "Agent");
      } else {
        append("Error: Invalid or missing response from server.", "System");
      }
    } catch (e: any) {
      setMessages((m) => m.filter((x) => x.id !== thinking.id));
      append(
        `Error: Failed to communicate with server. ${e?.message ?? e}`,
        "System"
      );
    } finally {
      setSending(false);
      autoResize();
    }
  }

  // login handled in LoginModal; on success we setMe and close modal

  async function logout() {
    try {
      // Fetch CSRF token first (validated)
      const token = await fetchCSRFToken();

      await fetch("/logout", {
        method: "POST",
        headers: {
          "X-CSRF-Token": token,
        },
        credentials: "include", // ensure cookies (incl. csrf_token) are sent
      });
    } catch (err) {
      console.error("Logout failed:", err);
      // Optionally show a toast; silent failure can be acceptable for logout
    } finally {
      setMe(null);
    }
  }

  function navigate(path: string) {
    const p = path.startsWith("/") ? path : "/" + path;
    if (window.location.pathname !== p) {
      window.history.pushState({}, "", p);
      // trigger route update
      window.dispatchEvent(new PopStateEvent("popstate"));
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
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
                  onClick={() => setShowAccountMenu((v) => !v)}
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
                        setShowAccountMenu(false);
                        // go to /account/settings and preserve existing hash
                        navigate("/account/settings");
                      }}
                    >
                      Settings
                    </button>
                    <button
                      role="menuitem"
                      className="menu-item"
                      onClick={() => {
                        setShowAccountMenu(false);
                        logout();
                      }}
                    >
                      Log out
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <>
                <button
                  className="link"
                  type="button"
                  onClick={() => setShowSignup(true)}
                >
                  Sign Up
                </button>
                <button
                  className="link"
                  type="button"
                  onClick={() => setShowLogin(true)}
                >
                  Log In
                </button>
              </>
            )}
          </nav>
        </div>
      </header>
      {route.startsWith("/account/settings") && (
        <div
          role="tablist"
          aria-label="Settings Sections"
          className="settings-tabs"
          style={{
            position: "sticky",
            top: 0,
            background: "#111827", // gray-900 for strong contrast
            color: "#F9FAFB", // gray-50 text
            zIndex: 1,
            borderBottom: "1px solid #111827",
            padding: "0.5rem 1rem",
            display: "flex",
            gap: "0.5rem",
          }}
        >
          <button
            role="tab"
            aria-selected={settingsTab === "profile"}
            className={settingsTab === "profile" ? "link active" : "link"}
            onClick={() => {
              setSettingsTab("profile");
              navigate("/account/settings");
            }}
            style={{
              color: settingsTab === "profile" ? "#FFFFFF" : "#D1D5DB", // white vs gray-300
              borderBottom:
                settingsTab === "profile"
                  ? "2px solid #60A5FA"
                  : "2px solid transparent", // blue-400 indicator
              paddingBottom: 4,
            }}
          >
            Profile
          </button>
          <button
            role="tab"
            aria-selected={settingsTab === "password"}
            className={settingsTab === "password" ? "link active" : "link"}
            onClick={() => {
              setSettingsTab("password");
              navigate("/account/settings/password");
            }}
            style={{
              color: settingsTab === "password" ? "#FFFFFF" : "#D1D5DB",
              borderBottom:
                settingsTab === "password"
                  ? "2px solid #60A5FA"
                  : "2px solid transparent",
              paddingBottom: 4,
            }}
          >
            Password
          </button>
          <button
            role="tab"
            aria-selected={settingsTab === "docker"}
            className={settingsTab === "docker" ? "link active" : "link"}
            onClick={() => {
              setSettingsTab("docker");
              navigate("/account/settings/docker");
            }}
            style={{
              color: settingsTab === "docker" ? "#FFFFFF" : "#D1D5DB",
              borderBottom:
                settingsTab === "docker"
                  ? "2px solid #60A5FA"
                  : "2px solid transparent",
              paddingBottom: 4,
            }}
          >
            Docker Settings
          </button>
        </div>
      )}
      {route.startsWith("/account/settings") ? (
        <SettingsPage
          me={me}
          tab={settingsTab}
          onChangeTab={setSettingsTab}
          onNameUpdated={(newName) =>
            setMe((me) => (me ? { ...me, name: newName } : me))
          }
        />
      ) : (
        <>
          <main id="chat" ref={chatRef} aria-live="polite" aria-atomic="false">
            <div className="chat-inner">
              {messages.map((m) => (
                <div
                  key={m.id}
                  className={`bubble ${
                    m.who === "Agent"
                      ? "agent-msg"
                      : m.who === "You"
                      ? "user-msg"
                      : "system-msg"
                  }`}
                >
                  {m.who === "Agent" ? (
                    <div
                      dangerouslySetInnerHTML={{ __html: safeMarked(m.text) }}
                    />
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
                  setInput(e.target.value);
                  autoResize();
                }}
                onKeyDown={onKeyDown}
                placeholder="Type a message..."
                rows={1}
                aria-label="Message input"
              />
              <button
                id="sendBtn"
                type="button"
                onClick={send}
                disabled={sending}
                aria-label="Send message"
              >
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

      <LoginModal
        open={showLogin}
        onClose={() => setShowLogin(false)}
        onSuccess={setMe}
      />
    </div>
  );
}

function safeMarked(s: string): string {
  try {
    if (typeof s !== "string") return "No or invalid response from server.";
    return marked.parse(s) as string;
  } catch (e: any) {
    return `Error rendering response: ${e?.message ?? e}`;
  }
}

type SettingsProps = {
  me: User | null;
  tab: "profile" | "password" | "docker";
  onChangeTab: (t: "profile" | "password" | "docker") => void;
  onNameUpdated: (newName: string) => void;
};

function SettingsPage({ me, tab, onChangeTab, onNameUpdated }: SettingsProps) {
  const [username, setUsername] = React.useState("");
  const [name, setName] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [message, setMessage] = React.useState<string | null>(null);

  const [curPass, setCurPass] = React.useState("");
  const [newPass, setNewPass] = React.useState("");
  const [confirmPass, setConfirmPass] = React.useState("");
  const [changing, setChanging] = React.useState(false);

  // SSH Key Generation state
  const [keyType, setKeyType] = React.useState<"ed25519" | "rsa">("ed25519");
  const [rsaBits, setRsaBits] = React.useState<number>(3072);
  const [keyComment, setKeyComment] = React.useState("");

  // Docker Settings (local state; persisted via future API)
  const [dockerContainer, setDockerContainer] =
    React.useState<string>("go-thing-arch");
  const [dockerImage, setDockerImage] =
    React.useState<string>("archlinux:latest");
  const [dockerArgs, setDockerArgs] = React.useState<string>("--privileged");
  const [dockerAutoRemove, setDockerAutoRemove] = React.useState<boolean>(true);
  const [dockerSaving, setDockerSaving] = React.useState<boolean>(false);
  const [dockerDockerfile, setDockerDockerfile] = React.useState<string>("");
  const [dockerSSHGenerating, setDockerSSHGenerating] =
    React.useState<boolean>(false);
  const [dockerSkipCache, setDockerSkipCache] = React.useState<boolean>(false);
  const [dockerBuilding, setDockerBuilding] = React.useState<boolean>(false);
  const [dockerStarting, setDockerStarting] = React.useState<boolean>(false);
  const [dockerRemoving, setDockerRemoving] = React.useState<boolean>(false);
  const [dockerStopping, setDockerStopping] = React.useState<boolean>(false);
  const [dockerRestarting, setDockerRestarting] =
    React.useState<boolean>(false);
  const [dockerPubKeyOut, setDockerPubKeyOut] = React.useState<string>("");
  const [keyPass, setKeyPass] = React.useState("");
  const [genLoading, setGenLoading] = React.useState(false);
  const [pubKey, setPubKey] = React.useState<string>("");
  const [privKey, setPrivKey] = React.useState<string>("");
  const [showPriv, setShowPriv] = React.useState(false);
  const [copyingWhich, setCopyingWhich] = React.useState<
    "public" | "private" | null
  >(null);
  const [downloadingWhich, setDownloadingWhich] = React.useState<
    "public" | "private" | null
  >(null);

  type ShellTab = {
    id: string;
    title: string;
    ws: WebSocket | null;
    output: string;
    input: string;
    renaming?: boolean;
    connected?: boolean;
    term?: Terminal;
    nudged?: boolean;
  };
  const [shellTabs, setShellTabs] = React.useState<ShellTab[]>([]);
  const [activeShellId, setActiveShellId] = React.useState<string | null>(null);
  const termContainersRef = React.useRef<Map<string, HTMLDivElement | null>>(
    new Map()
  );
  const termRefMap = React.useRef<Map<string, Terminal>>(new Map());
  const fitRefMap = React.useRef<Map<string, FitAddon>>(new Map());
  const attachRefMap = React.useRef<Map<string, AttachAddon>>(new Map());
  const resizeObserverRef = React.useRef<Map<string, ResizeObserver>>(
    new Map()
  );
  const resizeTimersRef = React.useRef<Map<string, number>>(new Map());
  const lastSizeRef = React.useRef<Map<string, { cols: number; rows: number }>>(
    new Map()
  );
  const reconnectTimersRef = React.useRef<Map<string, number>>(new Map());
  const reconnectAttemptsRef = React.useRef<Map<string, number>>(new Map());
  const nudgedRef = React.useRef<Map<string, boolean>>(new Map());
  const shellAreaRef = React.useRef<HTMLDivElement | null>(null);
  const [shellAreaHeight, setShellAreaHeight] = React.useState<number | null>(
    null
  );

  function hasOpenWS(id: string): boolean {
    const t = shellTabs.find((x) => x.id === id);
    return !!(t?.ws && t.ws.readyState === WebSocket.OPEN);
  }

  function registerTermContainer(id: string, el: HTMLDivElement | null) {
    termContainersRef.current.set(id, el);
    if (el) setupTerminalForTab(id);
  }

  function fitTerminalToContainer(id: string) {
    const t = shellTabs.find((x) => x.id === id);
    const container = termContainersRef.current.get(id);
    const term = t?.term;
    if (!t || !container || !term) return;
    // Measure character size
    const probe = document.createElement("span");
    probe.textContent = "W".repeat(20);
    probe.style.visibility = "hidden";
    probe.style.whiteSpace = "pre";
    probe.style.fontFamily =
      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';
    container.appendChild(probe);
    const w = probe.getBoundingClientRect().width / 20;
    const h = probe.getBoundingClientRect().height;
    probe.remove();
    if (!w || !h) return;
    const padding = 8;
    const cols = Math.max(
      20,
      Math.floor((container.clientWidth - padding) / w)
    );
    const rows = Math.max(
      5,
      Math.floor((container.clientHeight - padding) / h)
    );
    try {
      (term as any).resize(cols, rows);
    } catch {}
    if (t.ws && t.ws.readyState === WebSocket.OPEN) {
      try {
        t.ws.send(JSON.stringify({ type: "resize", cols, rows }));
      } catch {}
    }
  }

  // Ensure active tab terminal is created and resized on activation
  React.useEffect(() => {
    if (!activeShellId) return;
    setupTerminalForTab(activeShellId);
    fitTerminalToContainer(activeShellId);
  }, [activeShellId, shellTabs.length]);

  function setupTerminalForTab(id: string) {
    setShellTabs((tabs) => {
      const t = tabs.find((x) => x.id === id);
      if (!t) return tabs;
      if (t.term) return tabs; // already set up
      const container = termContainersRef.current.get(id);
      if (!container) return tabs;
      // Hard guard: if a terminal root already exists in this container, skip creating another
      try {
        if (container.querySelector(".xterm")) {
          return tabs;
        }
      } catch {}
      const term = new Terminal({
        convertEol: true,
        cursorBlink: true,
        lineHeight: 1,
        letterSpacing: 0,
        fontSize: 15,
        fontFamily:
          'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
        theme: { background: "#0B1220", foreground: "#E5E7EB" },
      });
      const fit = new FitAddon();
      term.loadAddon(fit as any);
      term.open(container);
      try {
        term.focus();
      } catch {}
      // Initial size using proposeDimensions
      try {
        sendResize(id);
      } catch {}
      // Ensure font metrics are loaded before final fit/resize
      try {
        const fontsAny: any = (document as any).fonts;
        if (fontsAny && typeof fontsAny.ready?.then === "function") {
          fontsAny.ready.then(() => {
            sendResize(id);
          });
        }
      } catch {}
      fitRefMap.current.set(id, fit);
      // Attach addon will handle both directions once WS is open
      // Store for out-of-react handlers
      termRefMap.current.set(id, term);
      // If a websocket already exists and is open, attach now
      try {
        const existingTab = tabs.find((x) => x.id === id);
        const existingWs = existingTab?.ws as WebSocket | null;
        const alreadyAttached = attachRefMap.current.has(id);
        if (
          existingWs &&
          existingWs.readyState === WebSocket.OPEN &&
          !alreadyAttached
        ) {
          const attach = new AttachAddon(existingWs, {
            bidirectional: true,
            useBinary: true,
          });
          term.loadAddon(attach as any);
          attachRefMap.current.set(id, attach);
          try {
            term.focus();
          } catch {}
          // Ensure terminal size synced after attaching
          setTimeout(() => {
            try {
              sendResize(id);
            } catch {}
          }, 0);
        }
      } catch {}
      // Ensure there is a connection attempt even if initial trigger was missed
      try {
        const existingTab = tabs.find((x) => x.id === id);
        const wsState = existingTab?.ws?.readyState;
        if (
          !existingTab?.ws ||
          wsState === WebSocket.CLOSED ||
          wsState === WebSocket.CLOSING
        ) {
          setTimeout(() => {
            try {
              connectWS(id);
            } catch {}
          }, 0);
        }
      } catch {}
      // Handle window resize
      const onWinResize = () => {
        const key = id;
        const prev = resizeTimersRef.current.get(key);
        if (prev) window.clearTimeout(prev);
        const tmr = window.setTimeout(() => {
          sendResize(id);
          try {
            (term as any).scrollToBottom();
          } catch {}
        }, 50);
        resizeTimersRef.current.set(key, tmr);
      };
      window.addEventListener("resize", onWinResize);
      // Save term in tab
      return tabs.map((x) => (x.id === id ? { ...x, term } : x));
    });
  }

  // Compute available space for the shell area and set explicit height
  function layoutShellArea() {
    const el = shellAreaRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const viewportH =
      window.innerHeight || document.documentElement.clientHeight || 0;
    // Reserve space for the fixed action bar (~64px) plus 8px gap
    const reserve = 72;
    let h = Math.max(160, Math.floor(viewportH - rect.top - reserve));
    // Avoid excessive height
    if (!Number.isFinite(h) || h > 2000) h = 2000;
    setShellAreaHeight(h);
    // Nudge active terminal to resize to the new height
    try {
      if (activeShellId) {
        const prev = resizeTimersRef.current.get("shellArea");
        if (prev) window.clearTimeout(prev);
        const tmr = window.setTimeout(() => {
          try {
            sendResize(activeShellId);
          } catch {}
        }, 0);
        resizeTimersRef.current.set("shellArea", tmr);
      }
    } catch {}
  }

  React.useEffect(() => {
    if (tab !== "docker") return;
    layoutShellArea();
    const onResize = () => layoutShellArea();
    window.addEventListener("resize", onResize);
    const raf = window.requestAnimationFrame(() => layoutShellArea());
    // Observe shell area element itself for size changes
    const el = shellAreaRef.current;
    let ro: ResizeObserver | null = null;
    if (el) {
      ro = new ResizeObserver(() => {
        try {
          if (activeShellId) sendResize(activeShellId);
        } catch {}
      });
      ro.observe(el);
    }
    return () => {
      window.removeEventListener("resize", onResize);
      window.cancelAnimationFrame(raf);
      try {
        ro?.disconnect();
      } catch {}
    };
  }, [tab, shellTabs.length, activeShellId]);

  // When active shell changes or shell height changes, ensure a resize
  React.useEffect(() => {
    if (!activeShellId) return;
    const prev = resizeTimersRef.current.get("activeShell");
    if (prev) window.clearTimeout(prev);
    const tmr = window.setTimeout(() => {
      try {
        sendResize(activeShellId);
      } catch {}
    }, 0);
    resizeTimersRef.current.set("activeShell", tmr);
  }, [activeShellId, shellAreaHeight]);

  // Global window resize fallback to ensure active terminal fits
  React.useEffect(() => {
    const onGlobalResize = () => {
      const prev = resizeTimersRef.current.get("globalWin");
      if (prev) window.clearTimeout(prev);
      const tmr = window.setTimeout(() => {
        try {
          if (activeShellId) sendResize(activeShellId);
        } catch {}
      }, 50);
      resizeTimersRef.current.set("globalWin", tmr);
    };
    window.addEventListener("resize", onGlobalResize);
    return () => window.removeEventListener("resize", onGlobalResize);
  }, [activeShellId]);

  // Attempt to reconnect WS for a tab
  function scheduleReconnect(id: string) {
    const tab = shellTabs.find((t) => t.id === id);
    if (!tab) return;
    const attempt = (reconnectAttemptsRef.current.get(id) || 0) + 1;
    reconnectAttemptsRef.current.set(id, attempt);
    const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000); // 1s,2s,4s,8s,10s cap
    const prev = reconnectTimersRef.current.get(id);
    if (prev) window.clearTimeout(prev);
    const tmr = window.setTimeout(() => connectWS(id), delay);
    reconnectTimersRef.current.set(id, tmr);
  }

  function computeInitialSize(id: string): { cols: number; rows: number } {
    let cols = 80,
      rows = 24;
    try {
      const fit = fitRefMap.current.get(id) as any;
      const dims = fit?.proposeDimensions?.();
      if (dims && dims.cols && dims.rows) {
        cols = Math.max(20, Math.min(240, (dims.cols as number) | 0));
        rows = Math.max(5, Math.min(120, (dims.rows as number) | 0));
      }
    } catch {}
    return { cols, rows };
  }

  function connectWS(id: string) {
    const existing = shellTabs.find((t) => t.id === id);
    if (!existing) return;
    const { cols, rows } = computeInitialSize(id);
    const url = `${wsBase()}/shell/ws/${encodeURIComponent(
      id
    )}?cols=${cols}&rows=${rows}`;
    try {
      console.debug("[shell] connecting", { id, url, cols, rows });
    } catch {}
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    setShellTabs((tabs) => tabs.map((t) => (t.id === id ? { ...t, ws } : t)));
    ws.onopen = () => {
      reconnectAttemptsRef.current.set(id, 0);
      const prevTmr = reconnectTimersRef.current.get(id);
      if (prevTmr) window.clearTimeout(prevTmr);
      setShellTabs((tabs) =>
        tabs.map((t) => (t.id === id ? { ...t, connected: true } : t))
      );
      setupTerminalForTab(id);
      try {
        const term = termRefMap.current.get(id);
        if (term) {
          // Replace any previous attach addon with a fresh one
          try {
            attachRefMap.current.get(id)?.dispose();
          } catch {}
          const attach = new AttachAddon(ws, {
            bidirectional: true,
            useBinary: true,
          });
          term.loadAddon(attach as any);
          attachRefMap.current.set(id, attach);
          try {
            term.focus();
          } catch {}
          // After opening, propose->resize->send
          setTimeout(() => {
            try {
              sendResize(id);
            } catch {}
          }, 0);
        }
      } catch {}
      // Observe container size changes if not already
      const containerEl = termContainersRef.current.get(id);
      if (containerEl && !resizeObserverRef.current.get(id)) {
        const ro = new ResizeObserver(() => {
          const key = id;
          const prev = resizeTimersRef.current.get(key);
          if (prev) window.clearTimeout(prev);
          const tmr = window.setTimeout(() => {
            sendResize(id);
          }, 50);
          resizeTimersRef.current.set(key, tmr);
        });
        ro.observe(containerEl);
        resizeObserverRef.current.set(id, ro);
      }
    };
    ws.onmessage = () => {};
    ws.onclose = () => {
      setShellTabs((tabs) =>
        tabs.map((t) => (t.id === id ? { ...t, connected: false } : t))
      );
      try {
        attachRefMap.current.get(id)?.dispose();
      } catch {}
      attachRefMap.current.delete(id);
      scheduleReconnect(id);
    };
    ws.onerror = () => {
      setShellTabs((tabs) =>
        tabs.map((t) => (t.id === id ? { ...t, connected: false } : t))
      );
      try {
        attachRefMap.current.get(id)?.dispose();
      } catch {}
      attachRefMap.current.delete(id);
      scheduleReconnect(id);
    };
  }

  React.useEffect(() => {
    let aborted = false;
    (async () => {
      try {
        const res = await fetch("/api/settings");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!aborted) {
          setUsername(data.username ?? "");
          setName(data.name ?? "");
        }
      } catch (e: any) {
        if (!aborted) setMessage(`Failed to load settings: ${e?.message ?? e}`);
      } finally {
        if (!aborted) setLoading(false);
      }
    })();
    return () => {
      aborted = true;
    };
  }, []);

  // Load Docker settings when tab becomes active
  React.useEffect(() => {
    if (tab !== "docker") return;
    let aborted = false;
    (async () => {
      try {
        const res = await fetch("/api/settings/docker");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const d = data?.docker || {};
        if (!aborted && typeof d === "object" && d) {
          if (typeof d.container === "string") setDockerContainer(d.container);
          if (typeof d.image === "string") setDockerImage(d.image);
          if (typeof d.args === "string") setDockerArgs(d.args);
          if (typeof d.auto_remove === "boolean")
            setDockerAutoRemove(d.auto_remove);
          if (typeof d.dockerfile === "string")
            setDockerDockerfile(d.dockerfile);
        }
      } catch (e: any) {
        if (!aborted)
          setMessage(`Failed to load Docker settings: ${e?.message ?? e}`);
      }
    })();
    return () => {
      aborted = true;
    };
  }, [tab]);

  // Inject CSS isolation for xterm to avoid global design rules affecting it
  React.useEffect(() => {
    const styleId = "term-host-css";
    if (!document.getElementById(styleId)) {
      const style = document.createElement("style");
      style.id = styleId;
      style.textContent = `
        .term-host, .term-host .xterm { position: relative; width: 100%; height: 100%; display: block; }
        .term-host .xterm-viewport { height: 100% !important; padding: 0 !important; }
        .term-host .xterm-rows { padding: 0 !important; }
      `;
      document.head.appendChild(style);
    }
  }, []);

  async function saveProfile(e: React.FormEvent) {
    e.preventDefault();
    setMessage(null);
    const trimmed = name.trim();
    if (!trimmed) {
      setMessage("Name is required");
      return;
    }
    setSaving(true);
    try {
      const token = await fetchCSRFToken();
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify({ name: trimmed }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      onNameUpdated(trimmed);
      setMessage("Profile updated");
    } catch (e: any) {
      setMessage(`Failed to update: ${e?.message ?? e}`);
    } finally {
      setSaving(false);
    }
  }

  async function changePassword(e: React.FormEvent) {
    e.preventDefault();
    setMessage(null);
    if (newPass.length < 8) {
      setMessage("New password must be at least 8 characters");
      return;
    }
    if (newPass !== confirmPass) {
      setMessage("New password and confirmation do not match");
      return;
    }
    setChanging(true);
    try {
      const token = await fetchCSRFToken();
      const res = await fetch("/api/settings/password", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify({
          current_password: curPass,
          new_password: newPass,
        }),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      setMessage("Password changed successfully");
      setCurPass("");
      setNewPass("");
      setConfirmPass("");
    } catch (e: any) {
      setMessage(`Failed to change password: ${e?.message ?? e}`);
    } finally {
      setChanging(false);
    }
  }

  async function saveDocker(e: React.FormEvent) {
    e.preventDefault();
    setMessage(null);
    setDockerSaving(true);
    try {
      const token = await fetchCSRFToken();
      const payload = {
        container: dockerContainer.trim(),
        image: dockerImage.trim(),
        args: dockerArgs,
        dockerfile: dockerDockerfile,
        auto_remove: !!dockerAutoRemove,
      };
      const res = await fetch("/api/settings/docker", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      setMessage("Docker settings saved");
    } catch (e: any) {
      setMessage(`Failed to save Docker settings: ${e?.message ?? e}`);
    } finally {
      setDockerSaving(false);
    }
  }

  async function generateContainerSSHKey(
    e: React.MouseEvent<HTMLButtonElement>
  ) {
    e.preventDefault();
    setMessage(null);
    setDockerSSHGenerating(true);
    setDockerPubKeyOut("");
    try {
      const token = await fetchCSRFToken();
      const res = await fetch("/api/docker/ssh-key", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        credentials: "include",
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      const data = await res.json();
      const pub =
        data && typeof data.public_key === "string"
          ? data.public_key.trim()
          : "";
      if (pub) {
        setDockerPubKeyOut(pub);
        setMessage("Generated ed25519 key inside container");
      } else {
        setMessage("Key generation succeeded but no public key returned");
      }
    } catch (e: any) {
      setMessage(`Failed to generate SSH key: ${e?.message ?? e}`);
    } finally {
      setDockerSSHGenerating(false);
    }
  }

  async function generateKeys(e: React.FormEvent) {
    e.preventDefault();
    setMessage(null);
    setGenLoading(true);
    setPubKey("");
    setPrivKey("");
    try {
      const token = await fetchCSRFToken();
      const payload: any = {
        type: keyType,
        comment: keyComment.trim(),
        passphrase: keyPass,
      };
      if (keyType === "rsa") payload.bits = rsaBits;
      const res = await fetch("/api/ssh-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      const data = await res.json();
      if (
        typeof data?.public_key === "string" &&
        typeof data?.private_key === "string"
      ) {
        setPubKey(data.public_key.trim());
        setPrivKey(data.private_key.trim());
      } else {
        throw new Error("Malformed response from server");
      }
    } catch (e: any) {
      setMessage(`Failed to generate keys: ${e?.message ?? e}`);
    } finally {
      setGenLoading(false);
    }
  }

  async function downloadDockerKey(which: "public" | "private") {
    try {
      setMessage(null);
      setDownloadingWhich(which);
      const res = await fetch(
        `/api/docker/ssh-keys/download?which=${encodeURIComponent(which)}`,
        {
          credentials: "include",
        }
      );
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(t || `HTTP ${res.status}`);
      }
      const text = await res.text();
      const filename = which === "public" ? "id_ed25519.pub" : "id_ed25519";
      download(text, filename);
    } catch (e: any) {
      setMessage(`Failed to download ${which} key: ${e?.message ?? e}`);
    } finally {
      setDownloadingWhich(null);
    }
  }

  async function copyDockerKey(which: "public" | "private") {
    try {
      setMessage(null);
      setCopyingWhich(which);
      const res = await fetch(
        `/api/docker/ssh-keys/download?which=${encodeURIComponent(which)}`,
        {
          credentials: "include",
        }
      );
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(t || `HTTP ${res.status}`);
      }
      const text = await res.text();
      await navigator.clipboard.writeText(text);
      setMessage(`Copied ${which} key to clipboard`);
      setTimeout(() => setMessage(null), 3000);
    } catch (e: any) {
      setMessage(`Failed to copy ${which} key: ${e?.message ?? e}`);
    } finally {
      setCopyingWhich(null);
    }
  }

  function download(text: string, filename: string) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function wsBase(): string {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    return `${proto}://${window.location.host}`;
  }

  async function openShellTab() {
    const id = crypto.randomUUID();
    const idx = shellTabs.length + 1;
    const title = `Shell ${idx}`;
    const newTab: ShellTab = {
      id,
      title,
      ws: null,
      output: "",
      input: "",
      connected: false,
    };
    setShellTabs((tabs) => [...tabs, newTab]);
    setActiveShellId(id);

    // Defer until container is rendered then connect WS
    setTimeout(() => {
      connectWS(id);
    }, 0);
  }

  function sendResize(id: string) {
    const term = termRefMap.current.get(id);
    const t = shellTabs.find((x) => x.id === id);
    if (!term || !t?.ws) return;
    let cols = (term as any)?.cols ?? 80;
    let rows = (term as any)?.rows ?? 24;
    try {
      const fit = fitRefMap.current.get(id) as any;
      const dims = fit?.proposeDimensions?.();
      if (dims && dims.cols && dims.rows) {
        const proposedCols = dims.cols | 0;
        const proposedRows = dims.rows | 0;
        // Clamp to sane bounds to avoid runaway growth loops
        cols = Math.max(20, Math.min(240, proposedCols));
        rows = Math.max(5, Math.min(120, proposedRows));
        const last = lastSizeRef.current.get(id);
        if (!last || last.cols !== cols || last.rows !== rows) {
          try {
            (term as any).resize(cols, rows);
          } catch {}
          lastSizeRef.current.set(id, { cols, rows });
        }
      }
    } catch {}
    if (t.ws.readyState === WebSocket.OPEN) {
      try {
        t.ws.send(JSON.stringify({ type: "resize", cols, rows }));
      } catch {}
    }
  }

  async function closeShellTab(id: string) {
    const t = shellTabs.find((x) => x.id === id);
    if (t?.ws) {
      try {
        t.ws.close();
      } catch {}
    }
    // Clear reconnect timer
    try {
      const tmr = reconnectTimersRef.current.get(id);
      if (tmr) window.clearTimeout(tmr);
    } catch {}
    // Dispose terminal
    const term = termRefMap.current.get(id);
    try {
      term?.dispose();
    } catch {}
    termRefMap.current.delete(id);
    // Best-effort notify server
    fetch(`/shell/sessions/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }).catch(() => {});
    setShellTabs((tabs) => tabs.filter((x) => x.id !== id));
    if (activeShellId === id) {
      const rest = shellTabs.filter((x) => x.id !== id);
      setActiveShellId(rest.length ? rest[rest.length - 1].id : null);
    }
  }

  function setTabTitle(id: string, title: string) {
    setShellTabs((tabs) =>
      tabs.map((t) => (t.id === id ? { ...t, title } : t))
    );
  }

  function sendToShell(id: string) {
    const t = shellTabs.find((x) => x.id === id);
    if (!t || !t.ws || t.ws.readyState !== WebSocket.OPEN) return;
    const line = t.input;
    if (!line) return;
    try {
      (t.ws as WebSocket).send(line);
      setShellTabs((tabs) =>
        tabs.map((x) => (x.id === id ? { ...x, input: "" } : x))
      );
    } catch {}
  }

  // xterm handles key events directly; no manual key mapping needed

  async function buildImage() {
    setMessage(null);
    setDockerBuilding(true);
    try {
      const token = await fetchCSRFToken();
      const res = await fetch("/api/docker/build", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify({ no_cache: !!dockerSkipCache }),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      setMessage("Image built successfully");
    } catch (e: any) {
      setMessage(`Failed to build image: ${e?.message ?? e}`);
    } finally {
      setDockerBuilding(false);
    }
  }

  async function startContainer() {
    setMessage(null);
    setDockerStarting(true);
    try {
      const token = await fetchCSRFToken();
      const res = await fetch("/api/docker/start", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      setMessage("Container started");
    } catch (e: any) {
      setMessage(`Failed to start container: ${e?.message ?? e}`);
    } finally {
      setDockerStarting(false);
    }
  }

  async function removeImage() {
    setMessage(null);
    setDockerRemoving(true);
    try {
      const token = await fetchCSRFToken();
      const res = await fetch("/api/docker/remove-image", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      setMessage("Image removed");
    } catch (e: any) {
      setMessage(`Failed to remove image: ${e?.message ?? e}`);
    } finally {
      setDockerRemoving(false);
    }
  }

  async function stopContainer() {
    setMessage(null);
    setDockerStopping(true);
    try {
      const token = await fetchCSRFToken();
      const res = await fetch("/api/docker/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      setMessage("Container stopped");
    } catch (e: any) {
      setMessage(`Failed to stop container: ${e?.message ?? e}`);
    } finally {
      setDockerStopping(false);
    }
  }

  async function restartContainer() {
    setMessage(null);
    setDockerRestarting(true);
    try {
      const token = await fetchCSRFToken();
      const res = await fetch("/api/docker/restart", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      setMessage("Container restarted");
    } catch (e: any) {
      setMessage(`Failed to restart container: ${e?.message ?? e}`);
    } finally {
      setDockerRestarting(false);
    }
  }

  return (
    <main
      className="settings"
      aria-live="polite"
      aria-atomic="false"
      style={{
        padding: "1rem",
        paddingBottom: tab === "docker" ? "8rem" : "1rem",
      }}
    >
      <h1 style={{ margin: "0 0 1rem 0" }}>User Settings</h1>
      {loading ? (
        <div>Loading…</div>
      ) : (
        <>
          {message && tab !== "docker" && (
            <div
              className="system-msg"
              role="status"
              style={{ marginBottom: "1rem" }}
            >
              {message}
            </div>
          )}
          {/* Tabs moved to fixed toolbar in App */}

          {tab === "profile" && (
            <section style={{ marginBottom: "2rem" }}>
              <h2 style={{ margin: "0 0 0.75rem 0" }}>Profile</h2>
              <form onSubmit={saveProfile}>
                <div
                  className="row"
                  style={{ gap: "0.5rem", alignItems: "baseline" }}
                >
                  <label style={{ minWidth: 100 }}>Username</label>
                  <input type="text" value={username} disabled aria-readonly />
                </div>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "baseline",
                    marginTop: "0.5rem",
                  }}
                >
                  <label style={{ minWidth: 100 }}>Display name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div style={{ marginTop: "0.75rem" }}>
                  <button type="submit" disabled={saving}>
                    Save
                  </button>
                </div>
              </form>
            </section>
          )}

          {tab === "password" && (
            <section>
              <h2 style={{ margin: "0 0 0.75rem 0" }}>Change Password</h2>
              <form onSubmit={changePassword}>
                <div
                  className="row"
                  style={{ gap: "0.5rem", alignItems: "baseline" }}
                >
                  <label style={{ minWidth: 160 }}>Current password</label>
                  <input
                    type="password"
                    value={curPass}
                    onChange={(e) => setCurPass(e.target.value)}
                    autoComplete="current-password"
                  />
                </div>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "baseline",
                    marginTop: "0.5rem",
                  }}
                >
                  <label style={{ minWidth: 160 }}>New password</label>
                  <input
                    type="password"
                    value={newPass}
                    onChange={(e) => setNewPass(e.target.value)}
                    autoComplete="new-password"
                  />
                </div>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "baseline",
                    marginTop: "0.5rem",
                  }}
                >
                  <label style={{ minWidth: 160 }}>Confirm new password</label>
                  <input
                    type="password"
                    value={confirmPass}
                    onChange={(e) => setConfirmPass(e.target.value)}
                    autoComplete="new-password"
                  />
                </div>
                <div style={{ marginTop: "0.75rem" }}>
                  <button type="submit" disabled={changing}>
                    Change password
                  </button>
                </div>
              </form>
            </section>
          )}

          {tab === "docker" && (
            <section>
              <h2 style={{ margin: "0 0 0.75rem 0" }}>Docker Settings</h2>
              <p style={{ marginTop: "0.25rem", color: "#666" }}>
                Configure the built-in Docker sandbox used by shell tools.
              </p>
              <form onSubmit={saveDocker}>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "baseline",
                    marginTop: "0.5rem",
                  }}
                >
                  <label style={{ minWidth: 220 }}>Container name</label>
                  <input
                    type="text"
                    placeholder="go-thing-arch"
                    value={dockerContainer}
                    onChange={(e) => setDockerContainer(e.target.value)}
                  />
                </div>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "baseline",
                    marginTop: "0.5rem",
                  }}
                >
                  <label style={{ minWidth: 220 }}>Image</label>
                  <input
                    type="text"
                    placeholder="archlinux:latest"
                    value={dockerImage}
                    onChange={(e) => setDockerImage(e.target.value)}
                  />
                </div>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "baseline",
                    marginTop: "0.5rem",
                  }}
                >
                  <label style={{ minWidth: 220 }}>Extra args</label>
                  <input
                    type="text"
                    placeholder="--privileged"
                    value={dockerArgs}
                    onChange={(e) => setDockerArgs(e.target.value)}
                  />
                </div>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "flex-start",
                    marginTop: "0.5rem",
                  }}
                >
                  <label style={{ minWidth: 220, paddingTop: 6 }}>
                    Dockerfile
                  </label>
                  <textarea
                    style={{
                      fontFamily:
                        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                      width: "100%",
                      minHeight: 180,
                    }}
                    placeholder={
                      "FROM archlinux:latest\nRUN pacman -Sy --noconfirm base-devel git sudo\n"
                    }
                    value={dockerDockerfile}
                    onChange={(e) => setDockerDockerfile(e.target.value)}
                  />
                </div>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "center",
                    marginTop: "0.5rem",
                  }}
                >
                  <label style={{ minWidth: 220 }}>
                    Auto remove container on exit
                  </label>
                  <input
                    type="checkbox"
                    checked={dockerAutoRemove}
                    onChange={(e) => setDockerAutoRemove(e.target.checked)}
                  />
                </div>
                {/* Bottom status bar above the action bar (Docker tab only) */}
                {message && (
                  <div
                    role="status"
                    className="system-msg"
                    style={{
                      position: "fixed",
                      left: 0,
                      right: 0,
                      bottom: "56px",
                      background: "#0B1220",
                      borderTop: "1px solid #1F2937",
                      borderBottom: "1px solid #1F2937",
                      padding: "0.5rem 1rem",
                      color: "#F9FAFB",
                      zIndex: 2,
                    }}
                  >
                    {message}
                  </div>
                )}

                {/* Fixed action bar at the bottom */}
                <div
                  style={{
                    position: "fixed",
                    left: 0,
                    right: 0,
                    bottom: 0,
                    background: "#111827",
                    borderTop: "1px solid #1F2937",
                    padding: "0.75rem 1rem",
                    display: "flex",
                    justifyContent: "space-between",
                    gap: "0.5rem",
                    zIndex: 2,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      gap: "0.5rem",
                      alignItems: "center",
                    }}
                  >
                    <button type="submit" disabled={dockerSaving}>
                      Save
                    </button>
                    <button
                      type="button"
                      onClick={generateContainerSSHKey}
                      disabled={dockerSSHGenerating}
                    >
                      {dockerSSHGenerating
                        ? "Generating…"
                        : "Generate ed25519 SSH key"}
                    </button>
                    <button
                      type="button"
                      onClick={() => downloadDockerKey("public")}
                      disabled={downloadingWhich !== null}
                    >
                      {downloadingWhich === "public"
                        ? "Downloading…"
                        : "Download public key"}
                    </button>
                    <button
                      type="button"
                      onClick={() => downloadDockerKey("private")}
                      disabled={downloadingWhich !== null}
                    >
                      {downloadingWhich === "private"
                        ? "Downloading…"
                        : "Download private key"}
                    </button>
                    <button
                      type="button"
                      onClick={() => copyDockerKey("public")}
                      disabled={copyingWhich !== null}
                    >
                      {copyingWhich === "public"
                        ? "Copying…"
                        : "Copy public key"}
                    </button>
                    <button
                      type="button"
                      onClick={() => copyDockerKey("private")}
                      disabled={copyingWhich !== null}
                    >
                      {copyingWhich === "private"
                        ? "Copying…"
                        : "Copy private key"}
                    </button>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      gap: "0.75rem",
                      alignItems: "center",
                    }}
                  >
                    <label
                      style={{
                        display: "flex",
                        gap: "0.25rem",
                        alignItems: "center",
                        color: "#D1D5DB",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={dockerSkipCache}
                        onChange={(e) => setDockerSkipCache(e.target.checked)}
                      />
                      Skip cache
                    </label>
                    <button
                      type="button"
                      onClick={buildImage}
                      disabled={dockerBuilding}
                    >
                      {dockerBuilding ? "Building…" : "Build"}
                    </button>
                    <button
                      type="button"
                      onClick={startContainer}
                      disabled={dockerStarting}
                    >
                      {dockerStarting ? "Starting…" : "Start"}
                    </button>
                    <button
                      type="button"
                      onClick={stopContainer}
                      disabled={dockerStopping}
                    >
                      {dockerStopping ? "Stopping…" : "Stop"}
                    </button>
                    <button
                      type="button"
                      onClick={restartContainer}
                      disabled={dockerRestarting}
                    >
                      {dockerRestarting ? "Restarting…" : "Restart"}
                    </button>
                    <button
                      type="button"
                      onClick={removeImage}
                      disabled={dockerRemoving}
                    >
                      {dockerRemoving ? "Removing…" : "Remove"}
                    </button>
                    <button type="button" onClick={openShellTab}>
                      Shell into
                    </button>
                  </div>
                </div>
                {dockerPubKeyOut && (
                  <div style={{ marginTop: "0.75rem" }}>
                    <label style={{ display: "block", marginBottom: 6 }}>
                      Public key
                    </label>
                    <textarea
                      readOnly
                      value={dockerPubKeyOut}
                      style={{
                        width: "100%",
                        minHeight: 60,
                        fontFamily:
                          'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                      }}
                    />
                  </div>
                )}
              </form>
              {/* Shell area */}
              <div
                ref={shellAreaRef}
                style={{
                  // marginTop: "1rem",
                  display: "flex",
                  flexDirection: "column",
                  height: shellAreaHeight ? `${shellAreaHeight}px` : undefined,
                  minHeight: 0,
                  border: "1px solid #1F2937",
                  borderRadius: 4,
                  overflow: "hidden",
                }}
              >
                {/* Tabs */}
                <div
                  style={{
                    display: "flex",
                    gap: "0.25rem",
                    padding: "0.5rem",
                    background: "#0B1220",
                    borderBottom: "1px solid #1F2937",
                    alignItems: "center",
                  }}
                >
                  {shellTabs.map((t) => (
                    <div
                      key={t.id}
                      onClick={() => setActiveShellId(t.id)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        padding: "0.25rem 0.5rem",
                        borderRadius: 4,
                        cursor: "pointer",
                        background:
                          activeShellId === t.id ? "#111827" : "transparent",
                        border:
                          activeShellId === t.id
                            ? "1px solid #1F2937"
                            : "1px solid transparent",
                        color: "#F9FAFB",
                      }}
                    >
                      {t.renaming ? (
                        <input
                          autoFocus
                          type="text"
                          value={t.title}
                          onChange={(e) => setTabTitle(t.id, e.target.value)}
                          onBlur={() =>
                            setShellTabs((tabs) =>
                              tabs.map((x) =>
                                x.id === t.id
                                  ? {
                                      ...x,
                                      renaming: false,
                                      title: (t.title || "Shell").trim(),
                                    }
                                  : x
                              )
                            )
                          }
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              (e.currentTarget as HTMLInputElement).blur();
                            }
                          }}
                          style={{
                            background: "#111827",
                            color: "#F9FAFB",
                            border: "1px solid #374151",
                            borderRadius: 4,
                            padding: "2px 4px",
                          }}
                        />
                      ) : (
                        <span
                          title={t.connected ? "connected" : "disconnected"}
                          onDoubleClick={() =>
                            setShellTabs((tabs) =>
                              tabs.map((x) =>
                                x.id === t.id ? { ...x, renaming: true } : x
                              )
                            )
                          }
                        >
                          {t.title}
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (t.renaming) {
                            setShellTabs((tabs) =>
                              tabs.map((x) =>
                                x.id === t.id ? { ...x, renaming: false } : x
                              )
                            );
                          } else {
                            closeShellTab(t.id);
                          }
                        }}
                        style={{
                          background: "transparent",
                          border: "none",
                          color: "#9CA3AF",
                        }}
                        aria-label={t.renaming ? "Finish rename" : "Close tab"}
                        title={t.renaming ? "Finish rename" : "Close tab"}
                      >
                        {t.renaming ? "✔" : "×"}
                      </button>
                    </div>
                  ))}
                  <button
                    type="button"
                    onClick={openShellTab}
                    style={{ marginLeft: "auto" }}
                  >
                    + New Tab
                  </button>
                </div>
                {/* Active terminal */}
                <div
                  style={{ flex: 1, display: "flex", flexDirection: "column" }}
                >
                  {shellTabs.length === 0 ? (
                    <div style={{ padding: "1rem", color: "#9CA3AF" }}>
                      No shell tabs. Click “Shell into” or “+ New Tab”.
                    </div>
                  ) : (
                    shellTabs.map((t) => (
                      <div
                        key={t.id}
                        style={{
                          display: activeShellId === t.id ? "flex" : "none",
                          flexDirection: "column",
                          height: "100%",
                          minHeight: 0,
                        }}
                      >
                        <div
                          ref={(el) =>
                            registerTermContainer(t.id, el as HTMLDivElement)
                          }
                          className="term-host"
                          style={{
                            flex: 1,
                            background: "#0B1220",
                            color: "#E5E7EB",
                            overflow: "hidden",
                            position: "relative",
                            width: "100%",
                            height: "100%",
                            padding: 0,
                            margin: 0,
                          }}
                        />
                        {/* direct typing: input row removed */}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </section>
          )}
        </>
      )}
    </main>
  );
}
