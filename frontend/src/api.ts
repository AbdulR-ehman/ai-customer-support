import type {
  AdminStats,
  AuditList,
  AuthResponse,
  ChatResponse,
  ConversationDetail,
  ConversationSummary,
  DocumentList,
  Feedback,
  KnowledgeDocument,
  MessageResponse,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfter?: number;

  constructor(status: number, code: string, message: string, retryAfter?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

let csrfToken = "";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(`/api${path}`, { ...init, headers, credentials: "include" });
  if (response.status === 204) return undefined as T;
  const body = (await response.json().catch(() => ({}))) as {
    error?: { code?: string; message?: string };
  };
  if (!response.ok) {
    const retry = Number(response.headers.get("Retry-After") ?? "") || undefined;
    throw new ApiError(
      response.status,
      body.error?.code ?? "request_failed",
      body.error?.message ?? "The request could not be completed.",
      retry,
    );
  }
  return body as T;
}

async function preauth<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = await request<{ csrf_token: string }>("/auth/csrf");
  csrfToken = token.csrf_token;
  return request<T>(path, init);
}

export const api = {
  async session(): Promise<AuthResponse> {
    const result = await request<AuthResponse>("/auth/session");
    csrfToken = result.csrf_token;
    return result;
  },
  async login(email: string, password: string): Promise<AuthResponse> {
    const result = await preauth<AuthResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    csrfToken = result.csrf_token;
    return result;
  },
  async register(email: string, password: string, displayName: string): Promise<MessageResponse> {
    return preauth<MessageResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password, display_name: displayName || null }),
    });
  },
  logout: () => request<MessageResponse>("/auth/logout", { method: "POST" }),
  conversations: () => request<ConversationSummary[]>("/chat/conversations"),
  conversation: (id: string) => request<ConversationDetail>(`/chat/conversations/${encodeURIComponent(id)}`),
  sendMessage: (question: string, conversationId?: string) =>
    request<ChatResponse>("/chat/messages", {
      method: "POST",
      body: JSON.stringify({ question, conversation_id: conversationId ?? null }),
    }),
  deleteConversation: (id: string) => request<void>(`/chat/conversations/${encodeURIComponent(id)}`, { method: "DELETE" }),
  feedback: (messageId: string, rating: "up" | "down", comment?: string) =>
    request<Feedback>(`/chat/messages/${encodeURIComponent(messageId)}/feedback`, {
      method: "PUT",
      body: JSON.stringify({ rating, comment: comment || null }),
    }),
  adminStats: () => request<AdminStats>("/admin/stats"),
  documents: (status?: string) =>
    request<DocumentList>(`/admin/documents${status ? `?status=${encodeURIComponent(status)}` : ""}`),
  document: (id: string) => request<KnowledgeDocument & { events: unknown[] }>(`/admin/documents/${encodeURIComponent(id)}`),
  upload: (file: File) => {
    const body = new FormData();
    body.append("file", file);
    return request<{ document: KnowledgeDocument; created: boolean; message: string }>("/admin/documents", { method: "POST", body });
  },
  reindex: (id: string) => request<MessageResponse>(`/admin/documents/${encodeURIComponent(id)}/reindex`, { method: "POST" }),
  deleteDocument: (id: string) => request<MessageResponse>(`/admin/documents/${encodeURIComponent(id)}`, { method: "DELETE" }),
  audit: () => request<AuditList>("/admin/audit"),
};
