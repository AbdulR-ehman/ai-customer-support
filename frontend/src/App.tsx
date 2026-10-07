import { useEffect, useState } from "react";
import { api, ApiError } from "./api";
import type { ConversationDetail, ConversationSummary, User } from "./types";
import { AdminPanel } from "./admin/AdminPanel";
import { AuthPanel } from "./auth/AuthPanel";
import { ChatPanel } from "./chat/ChatPanel";
import { ErrorBoundary } from "./components/ErrorBoundary";

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);
  const [authMessage, setAuthMessage] = useState("");

  useEffect(() => {
    api.session().then((result) => setUser(result.user)).catch(() => undefined).finally(() => setReady(true));
  }, []);

  async function logout() {
    try { await api.logout(); } finally { setUser(null); }
  }

  if (!ready) return <div className="loading-screen">Loading Acme Support…</div>;

  return (
    <ErrorBoundary>
      <div className="app-shell">
        <header className="topbar">
          <div className="brand"><span className="brand-mark">A</span><span>Acme Support <small>AI customer care</small></span></div>
          {user && <div className="topbar-actions"><span className="user-chip" data-testid="current-user">{user.display_name || user.email}</span><button className="button ghost" onClick={logout} data-testid="logout">Sign out</button></div>}
        </header>
        {authMessage && <div className="global-message" role="status">{authMessage}</div>}
        {!user ? <AuthPanel onAuthenticated={(next) => { setUser(next); setAuthMessage(""); }} /> : user.role === "admin" ? <AdminPanel user={user} /> : <CustomerShell onLogout={logout} />}
      </div>
    </ErrorBoundary>
  );
}

function CustomerShell({ onLogout }: { onLogout: () => void }) {
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [active, setActive] = useState<ConversationDetail | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  async function refresh() {
    try { setConversations(await api.conversations()); } catch (cause) { setError(cause instanceof ApiError ? cause.message : "Unable to load conversations."); } finally { setLoading(false); }
  }
  useEffect(() => { void refresh(); }, []);

  async function openConversation(id: string) {
    try { setActive(await api.conversation(id)); } catch (cause) { setError(cause instanceof ApiError ? cause.message : "Unable to open that conversation."); }
  }
  async function removeConversation(id: string) {
    if (!window.confirm("Delete this conversation and its messages?")) return;
    try { await api.deleteConversation(id); setActive(null); await refresh(); } catch (cause) { setError(cause instanceof ApiError ? cause.message : "Unable to delete that conversation."); }
  }
  async function afterMessage(detail: ConversationDetail, selectedId: string) {
    setActive(detail); setConversations(await api.conversations()); setError(""); void selectedId;
  }

  return (
    <main className="customer-layout">
      <aside className="sidebar">
        <div className="sidebar-heading"><h2>Conversations</h2><button className="button primary small" onClick={() => setActive(null)} data-testid="new-conversation">+ New</button></div>
        {error && <p className="inline-error" role="alert">{error}</p>}
        {loading ? <p className="muted">Loading…</p> : conversations.length === 0 ? <p className="muted">No conversations yet.</p> : <ul className="conversation-list">{conversations.map((item) => <li key={item.id}><button className={`conversation-item ${active?.id === item.id ? "active" : ""}`} onClick={() => void openConversation(item.id)}><strong>{item.title}</strong><span>{item.message_count} messages</span></button><button className="icon-button danger" aria-label={`Delete ${item.title}`} onClick={() => void removeConversation(item.id)}>×</button></li>)}</ul>}
        <div className="sidebar-footer"><button className="button ghost full" onClick={onLogout}>Sign out</button></div>
      </aside>
      <section className="chat-area"><ChatPanel conversation={active} onConversationChange={afterMessage} /></section>
    </main>
  );
}
