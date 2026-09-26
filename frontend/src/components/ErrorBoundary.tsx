import { Component, type ErrorInfo, type ReactNode } from "react";

export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("UI error", error.name, info.componentStack); }
  render() { return this.state.failed ? <main className="auth-shell"><section className="auth-card"><h1>Something went wrong</h1><p>The application hit an unexpected UI error. Reload the page to try again.</p><button className="button primary" onClick={() => window.location.reload()}>Reload</button></section></main> : this.props.children; }
}
