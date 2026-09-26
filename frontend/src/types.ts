export interface MessageResponse {
  message: string;
}


export type Role = "customer" | "admin";

export interface User {
  id: string;
  email: string;
  display_name: string | null;
  role: Role;
  created_at: string | null;
}

export interface AuthResponse {
  user: User;
  message: string | null;
  csrf_token: string;
}

export interface Source {
  document_id: string;
  document_title: string;
  snippet: string;
  score: number;
  position: number;
}

export interface Feedback {
  rating: "up" | "down";
  comment: string | null;
}

export interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  created_at: string;
  blocked: boolean;
  sources: Source[];
  feedback: Feedback | null;
}

export interface ConversationSummary {
  id: string;
  title: string;
  message_count: number;
  created_at: string;
  last_message_at: string | null;
}

export interface ConversationDetail extends ConversationSummary {
  messages: Message[];
}

export interface ChatResponse {
  conversation_id: string;
  conversation_title: string;
  conversation_is_new: boolean;
  user_message: Message;
  assistant_message: Message;
  grounded: boolean;
}

export type DocumentStatus = "pending" | "processing" | "indexed" | "failed";

export interface KnowledgeDocument {
  id: string;
  title: string;
  original_filename: string;
  content_type: string;
  source: "upload" | "seed";
  size_bytes: number;
  status: DocumentStatus;
  error_message: string | null;
  chunk_count: number;
  page_count: number | null;
  created_at: string;
  indexed_at: string | null;
  uploaded_by: string | null;
}

export interface DocumentList {
  items: KnowledgeDocument[];
  page: { total: number; limit: number; offset: number };
}

export interface KnowledgeStats {
  documents: number;
  documents_indexed: number;
  documents_pending: number;
  documents_processing: number;
  documents_failed: number;
  chunks: number;
  chunks_flagged: number;
}

export interface AdminStats {
  users: number;
  admins: number;
  conversations: number;
  feedback_total: number;
  feedback_up: number;
  feedback_down: number;
  audit_entries: number;
  knowledge: KnowledgeStats;
}

export interface AuditEntry {
  id: number;
  action: string;
  actor_user_id: string | null;
  actor_role: string | null;
  target_type: string | null;
  target_id: string | null;
  detail: string | null;
  request_id: string | null;
  ip_address: string | null;
  created_at: string;
}

export interface AuditList {
  items: AuditEntry[];
  page: { total: number; limit: number; offset: number };
}
