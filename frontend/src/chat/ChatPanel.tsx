import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api";
import type { ConversationDetail, Message } from "../types";

export function ChatPanel({ conversation, onConversationChange }: { conversation: ConversationDetail | null; onConversationChange: (conversation: ConversationDetail, id: string) => Promise<void> }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => { setMessages(conversation?.messages ?? []); setError(""); }, [conversation]);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages.length]);

  async function send(event: React.FormEvent) {
    event.preventDefault(); const text = question.trim(); if (!text || busy) return;
    setBusy(true); setError(""); setQuestion("");
    try {
      const result = await api.sendMessage(text, conversation?.id);
      const detail = { ...(conversation ?? { id: result.conversation_id, title: result.conversation_title, message_count: 2, created_at: "", last_message_at: "" }), id: result.conversation_id, title: result.conversation_title, message_count: (conversation?.messages.length ?? 0) + 2, messages: [...(conversation?.messages ?? []), result.user_message, result.assistant_message] };
      setMessages(detail.messages); await onConversationChange(detail, result.conversation_id);
    } catch (cause) {
      setQuestion(text);
      const message = cause instanceof ApiError ? cause.message : "The assistant could not answer right now.";
      setError(cause instanceof ApiError && cause.status === 429 ? `${message}${cause.retryAfter ? ` Try again in ${cause.retryAfter} seconds.` : ""}` : message);
    } finally { setBusy(false); }
  }
  async function feedback(message: Message, rating: "up" | "down") {
    try { await api.feedback(message.id, rating); setMessages((current) => current.map((item) => item.id === message.id ? { ...item, feedback: { rating, comment: null } } : item)); }
    catch (cause) { setError(cause instanceof ApiError ? cause.message : "Feedback could not be saved."); }
  }
  return <div className="chat-panel"><header className="chat-heading"><div><div className="eyebrow">KNOWLEDGE ASSISTANT</div><h1>{conversation?.title ?? "Welcome to Acme Support"}</h1></div><span className="online-badge">● Online</span></header><div className="messages" aria-live="polite" data-testid="messages">{messages.length === 0 ? <div className="welcome-card"><span className="welcome-icon">✦</span><h2>What can we help you with?</h2><p>Ask about products, orders, refunds, account access, or troubleshooting.</p><div className="suggestions"><button onClick={() => setQuestion("What is your refund policy?")}>Refund policy</button><button onClick={() => setQuestion("What are your support hours?")}>Support hours</button><button onClick={() => setQuestion("How do I reset my password?")}>Account help</button></div></div> : messages.map((item) => <article className={`message ${item.role}`} key={item.id}><div className="avatar">{item.role === "assistant" ? "A" : "You"}</div><div className="message-body"><div className="message-meta"><strong>{item.role === "assistant" ? "Acme Assistant" : "You"}</strong><time>{new Date(item.created_at).toLocaleString()}</time></div><p>{item.content}</p>{item.sources.length > 0 && <details className="sources"><summary>{item.sources.length} source{item.sources.length === 1 ? "" : "s"}</summary>{item.sources.map((source, index) => <div className="source" key={`${source.document_id}-${index}`}><strong>{source.document_title}</strong><span>Section {source.position} · {Math.round(source.score)} relevance</span><p>{source.snippet}</p></div>)}</details>}{item.role === "assistant" && <div className="feedback"><span>Was this helpful?</span><button className={item.feedback?.rating === "up" ? "active" : ""} aria-label="Helpful" onClick={() => void feedback(item, "up")} data-testid="feedback-up">↑</button><button className={item.feedback?.rating === "down" ? "active" : ""} aria-label="Not helpful" onClick={() => void feedback(item, "down")} data-testid="feedback-down">↓</button></div>}</div></article>)}<div ref={endRef} /></div>{error && <div className="chat-alert" role="alert">{error}<button aria-label="Dismiss" onClick={() => setError("")}>×</button></div>}<form className="composer" onSubmit={send}><label className="sr-only" htmlFor="question">Your question</label><textarea id="question" value={question} onChange={(e) => setQuestion(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); e.currentTarget.form?.requestSubmit(); } }} placeholder="Ask a question about Acme Support…" maxLength={2000} rows={2} disabled={busy} data-testid="message-input" /><div className="composer-footer"><span>{question.length} / 2,000</span><button className="button primary" disabled={busy || !question.trim()} data-testid="send-message">{busy ? "Thinking…" : "Send"}</button></div></form></div>;
}
