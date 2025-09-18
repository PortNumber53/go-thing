import React from "react";
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
  const getTabFromPath = (): "profile" | "password" | "docker" | "personal" => {
    const p = (window.location.pathname || "/").toLowerCase();
    if (!p.startsWith("/account/settings")) return "profile";
    const parts = p.split("/").filter(Boolean); // e.g., ["account","settings","docker"]
    const maybe = parts[2] || "";
    if (maybe === "password") return "password";
    if (maybe === "docker") return "docker";
    if (maybe === "personal") return "personal";
    return "profile";
  };

  const [route, setRoute] = React.useState<string>(() => getRoute());
  // Settings tab state lifted to App for a fixed toolbar under header
  const [settingsTab, setSettingsTab] = React.useState<
    "profile" | "password" | "docker" | "personal"
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
          <button
            role="tab"
            aria-selected={settingsTab === "personal"}
            className={settingsTab === "personal" ? "link active" : "link"}
            onClick={() => {
              setSettingsTab("personal");
              navigate("/account/settings/personal");
            }}
            style={{
              color: settingsTab === "personal" ? "#FFFFFF" : "#D1D5DB",
              borderBottom:
                settingsTab === "personal"
                  ? "2px solid #60A5FA"
                  : "2px solid transparent",
              paddingBottom: 4,
            }}
          >
            Persona Settings
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
  tab: "profile" | "password" | "docker" | "personal";
  onChangeTab: (t: "profile" | "password" | "docker" | "personal") => void;
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

  // Personal Settings: System Prompts state
  type Prompt = {
    id: number;
    name: string;
    content: string;
    preferred_llms: string[];
    active: boolean;
    default: boolean;
    created_at?: string;
    updated_at?: string;
  };
  const [prompts, setPrompts] = React.useState<Prompt[]>([]);
  const [selectedPromptId, setSelectedPromptId] = React.useState<number | null>(
    null
  );
  const [pName, setPName] = React.useState("");
  const [pContent, setPContent] = React.useState("");
  const [pLLMs, setPLLMs] = React.useState(""); // comma-separated
  const [pActive, setPActive] = React.useState(false);
  const [pDefault, setPDefault] = React.useState(false);
  const [pLoading, setPLoading] = React.useState(false);
  const [pSaving, setPSaving] = React.useState(false);

  React.useEffect(() => {
    if (tab !== "personal") return;
    let aborted = false;
    setPLoading(true);
    (async () => {
      try {
        const res = await fetch("/api/settings/prompts");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const list: Prompt[] = Array.isArray(data?.prompts) ? data.prompts : [];
        if (!aborted) {
          setPrompts(list);
          if (list.length > 0) {
            const first = list[0];
            setSelectedPromptId(first.id);
            setPName(first.name || "");
            setPContent(first.content || "");
            setPLLMs((first.preferred_llms || []).join(", "));
            setPActive(!!first.active);
            setPDefault(!!first.default);
          } else {
            setSelectedPromptId(null);
            setPName("");
            setPContent("");
            setPLLMs("");
            setPActive(false);
            setPDefault(false);
          }
        }
      } catch (e: any) {
        if (!aborted)
          setMessage(`Failed to load System Prompts: ${e?.message ?? e}`);
      } finally {
        if (!aborted) setPLoading(false);
      }
    })();
    return () => {
      aborted = true;
    };
  }, [tab]);

  function onSelectPrompt(p: Prompt) {
    setSelectedPromptId(p.id);
    setPName(p.name || "");
    setPContent(p.content || "");
    setPLLMs((p.preferred_llms || []).join(", "));
    setPActive(!!p.active);
    setPDefault(!!p.default);
    setMessage(null);
  }

  function newPrompt() {
    setSelectedPromptId(null);
    setPName("");
    setPContent("");
    setPLLMs("");
    setPActive(false);
    setPDefault(false);
    setMessage(null);
  }

  async function errorMessageFromResponse(res: Response): Promise<string> {
    try {
      const text = await res.text();
      if (!text) return `HTTP ${res.status}`;
      try {
        const json = JSON.parse(text);
        if (json && typeof json.error === "string") return json.error;
      } catch (_) {}
      return text;
    } catch (_) {
      return `HTTP ${res.status}`;
    }
  }

  async function savePrompt() {
    try {
      setPSaving(true);
      setMessage(null);
      const name = pName.trim();
      if (!name || !pContent.trim()) {
        setMessage("Name and content are required");
        return;
      }
      const preferred_llms = pLLMs
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const token = await fetchCSRFToken();
      if (selectedPromptId == null) {
        const res = await fetch("/api/settings/prompts", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
          },
          body: JSON.stringify({
            name,
            content: pContent,
            preferred_llms,
            active: !!pActive,
            default: !!pDefault,
          }),
        });
        if (!res.ok) throw new Error(await errorMessageFromResponse(res));
        const payload = await res.json();
        const created: Prompt | null = payload?.prompt || null;
        if (!created) throw new Error("Malformed response");
        // Update local state without refetch; if default, clear others
        setPrompts((prev) => {
          const cleared = created.default
            ? prev.map((p) => ({ ...p, default: false }))
            : prev;
          return [created, ...cleared.filter((p) => p.id !== created.id)];
        });
        // Select created prompt
        onSelectPrompt(created);
        setMessage("Prompt created");
      } else {
        const res = await fetch(`/api/settings/prompts/${selectedPromptId}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
          },
          body: JSON.stringify({
            name,
            content: pContent,
            preferred_llms,
            active: !!pActive,
            default: !!pDefault,
          }),
        });
        if (!res.ok) throw new Error(await errorMessageFromResponse(res));
        const payload = await res.json();
        const updated: Prompt | null = payload?.prompt || null;
        if (!updated) throw new Error("Malformed response");
        // Update local state: replace the item; if default true, clear others
        setPrompts((prev) => {
          let next = prev.map((p) => (p.id === updated.id ? updated : p));
          if (updated.default) {
            next = next.map((p) =>
              p.id === updated.id ? p : { ...p, default: false }
            );
          }
          // Move updated to front to roughly mimic updated_at DESC
          return [updated, ...next.filter((p) => p.id !== updated.id)];
        });
        onSelectPrompt(updated);
        setMessage("Prompt saved");
      }
    } catch (e: any) {
      setMessage(typeof e?.message === "string" ? e.message : "Failed to save");
    } finally {
      setPSaving(false);
    }
  }

  async function deletePrompt() {
    if (selectedPromptId == null) return;
    try {
      setMessage(null);
      const token = await fetchCSRFToken();
      const res = await fetch(`/api/settings/prompts/${selectedPromptId}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": token },
      });
      if (!res.ok) {
        throw new Error(await errorMessageFromResponse(res));
      }
      // Update local state instead of reloading
      setPrompts((prev) => {
        const next = prev.filter((p) => p.id !== selectedPromptId);
        if (next.length > 0) {
          onSelectPrompt(next[0]);
        } else {
          newPrompt();
        }
        return next;
      });
      setMessage("Prompt deleted");
    } catch (e: any) {
      setMessage(
        typeof e?.message === "string" ? e.message : "Failed to delete"
      );
    }
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

  return (
    <main
      className="settings"
      aria-live="polite"
      aria-atomic="false"
      style={{
        padding: "1rem",
        paddingBottom: tab === "docker" || tab === "personal" ? "8rem" : "1rem",
      }}
    >
      <h1 style={{ margin: "0 0 1rem 0" }}>User Settings</h1>
      {loading ? (
        <div>Loading…</div>
      ) : (
        <>
          {message && tab !== "docker" && tab !== "personal" && (
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

          {tab === "personal" && (
            <section
              style={{
                display: "grid",
                gridTemplateColumns: "280px 1fr",
                gap: "1rem",
              }}
            >
              <div>
                <h2 style={{ margin: "0 0 0.5rem 0" }}>System Prompts</h2>
                {pLoading ? (
                  <div>Loading…</div>
                ) : (
                  <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                    {prompts.map((p) => (
                      <li key={p.id} style={{ marginBottom: 6 }}>
                        <button
                          className={
                            selectedPromptId === p.id ? "link active" : "link"
                          }
                          onClick={() => onSelectPrompt(p)}
                          style={{ width: "100%", textAlign: "left" }}
                        >
                          {p.name}
                          {p.default
                            ? "  • default"
                            : p.active
                            ? "  • active"
                            : ""}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
                {/* New Prompt moved to bottom action bar */}
              </div>
              <div>
                <h2 style={{ margin: "0 0 0.5rem 0" }}>
                  {selectedPromptId == null ? "New Prompt" : "Edit Prompt"}
                </h2>
                <div
                  className="row"
                  style={{ gap: "0.5rem", alignItems: "baseline" }}
                >
                  <label style={{ minWidth: 120 }}>Name</label>
                  <input
                    type="text"
                    value={pName}
                    onChange={(e) => setPName(e.target.value)}
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
                  <label style={{ minWidth: 120, paddingTop: 6 }}>
                    System Prompt (Markdown)
                  </label>
                  <textarea
                    style={{
                      fontFamily:
                        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                      width: "100%",
                      minHeight: 220,
                    }}
                    placeholder={
                      "# Instructions\nYou are a helpful assistant..."
                    }
                    value={pContent}
                    onChange={(e) => setPContent(e.target.value)}
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
                  <label style={{ minWidth: 120 }}>Preferred LLMs</label>
                  <input
                    type="text"
                    placeholder="comma-separated (e.g., gemini-1.5-pro, gpt-4o, claude-3.5-sonnet)"
                    value={pLLMs}
                    onChange={(e) => setPLLMs(e.target.value)}
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
                  <label style={{ minWidth: 120 }}>Active</label>
                  <input
                    type="checkbox"
                    checked={pActive || pDefault}
                    onChange={(e) => setPActive(e.target.checked)}
                    disabled={pDefault}
                    title={pDefault ? "Default prompt cannot be disabled" : ""}
                  />
                </div>
                <div
                  className="row"
                  style={{
                    gap: "0.5rem",
                    alignItems: "center",
                    marginTop: "0.25rem",
                  }}
                >
                  <label style={{ minWidth: 120 }}>Default</label>
                  <input
                    type="checkbox"
                    checked={pDefault}
                    onChange={(e) => setPDefault(e.target.checked)}
                  />
                </div>
                {/* Bottom status bar above the action bar (Persona tab only) */}
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
                    alignItems: "center",
                    gap: "0.5rem",
                    zIndex: 2,
                  }}
                >
                  <div style={{ display: "flex", gap: "0.5rem" }}>
                    <button type="button" onClick={newPrompt}>
                      New Prompt
                    </button>
                  </div>
                  <div style={{ display: "flex", gap: "0.5rem" }}>
                    <button
                      type="button"
                      onClick={savePrompt}
                      disabled={pSaving}
                    >
                      {pSaving ? "Saving…" : "Save"}
                    </button>
                  {selectedPromptId != null && (
                    <button
                      type="button"
                      onClick={deletePrompt}
                      disabled={pDefault}
                      title={pDefault ? "Cannot delete the default prompt" : ""}
                    >
                      Delete
                    </button>
                  )}
                  </div>
                </div>
              </div>
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
                    justifyContent: "flex-end",
                    gap: "0.5rem",
                    zIndex: 2,
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
                    {copyingWhich === "public" ? "Copying…" : "Copy public key"}
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
            </section>
          )}
        </>
      )}
    </main>
  );
}
