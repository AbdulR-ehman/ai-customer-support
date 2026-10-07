import { useState } from "react";
import { api, ApiError } from "../api";
import type { User } from "../types";

export function AuthPanel({ onAuthenticated }: { onAuthenticated: (user: User) => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(""); setNotice(""); setBusy(true);
    try {
      if (mode === "login") { const result = await api.login(email, password); onAuthenticated(result.user); }
      else { await api.register(email, password, displayName); setMode("login"); setPassword(""); setNotice("Your account is ready. Sign in to continue."); }
    } catch (cause) { setError(cause instanceof ApiError ? cause.message : "Unable to continue. Please try again."); }
    finally { setBusy(false); }
  }
  return <main className="auth-shell"><section className="auth-card" aria-labelledby="auth-title"><div className="eyebrow">ACME SUPPORT</div><h1 id="auth-title">How can we help?</h1><p className="auth-intro">Ask our support assistant for clear answers backed by Acme's support knowledge.</p><div className="tabs" role="tablist"><button className={mode === "login" ? "selected" : ""} onClick={() => { setMode("login"); setError(""); }} role="tab" aria-selected={mode === "login"}>Sign in</button><button className={mode === "register" ? "selected" : ""} onClick={() => { setMode("register"); setError(""); }} role="tab" aria-selected={mode === "register"} data-testid="register-tab">Create account</button></div>{(error || notice) && <div className={error ? "form-alert error" : "form-alert success"} role="alert">{error || notice}</div>}<form onSubmit={submit}><label>Email address<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" data-testid="email" /></label>{mode === "register" && <label>Name <span className="optional">optional</span><input type="text" maxLength={80} value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" /></label>}<label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={mode === "register" ? 10 : 1} maxLength={128} autoComplete={mode === "register" ? "new-password" : "current-password"} data-testid="password" /></label><button className="button primary full" disabled={busy} data-testid="submit-auth">{busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}</button></form><p className="auth-note">Your support conversations are private to your account.</p></section></main>;
}
