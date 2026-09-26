# Acme Support AI

An offline, zero-cost AI customer-support system: a grounded chat assistant backed by a curated
knowledge base, plus an administrator console for managing that knowledge.

| Layer | Technology |
| --- | --- |
| Backend | FastAPI · Pydantic v2 · SQLAlchemy 2 · SQLite (WAL) · Python ≥ 3.11 |
| Frontend | React 19 · Vite 7 · TypeScript 5 (no `VITE_*` secrets, no `dangerouslySetInnerHTML`) |
| AI | `MockAIProvider` only — deterministic, offline, template-based; no model downloads, no API keys, no paid services |
| Retrieval | SQLite FTS5 + `bm25()` ranking with a term-coverage floor (no embeddings) |
| Auth | Argon2id password hashing · opaque server-side sessions (SHA-256 hashed at rest) · CSRF double-submit token |

Everything runs on loopback (`127.0.0.1`) with no external network calls at runtime.

---

## 1. What it does

**Customer experience**

* Register / sign in / sign out, change password, delete account.
* Ask questions in a chat UI; answers are generated **only** from retrieved knowledge-base text and
  carry explicit citations back to the source document and chunk.
* When retrieval finds nothing relevant the assistant refuses instead of inventing an answer.
* Prompt-injection attempts (direct or smuggled through a document) are refused.
* Conversation history, per-answer thumbs up/down feedback, and conversation deletion.

**Administrator experience**

* Dashboard totals (documents, indexed chunks, users, conversations, feedback).
* Knowledge base: upload (TXT / Markdown / PDF, ≤ 5 MB), list, inspect, re-index, delete.
* Append-only audit log of security-relevant actions (logins, uploads, re-index, deletes, denials).

**Grounded-answer contract**

1. The question is normalised and screened by the input guard.
2. SQLite FTS5 retrieves candidate chunks ranked by BM25; a minimum term-coverage ratio
   (`MIN_TERM_COVERAGE = 0.3`) discards incidental single-keyword matches.
3. Only if enough relevant context survives does the provider produce an answer, which is then
   passed through the output guard (canary/secret/path redaction + length cap).
4. Otherwise the deterministic "I don't have enough information…" refusal is returned.

---

## 2. Project layout

```
AI CUSTOMER SUPPORT/
├─ backend/
│  ├─ app/
│  │  ├─ ai/            provider interface, mock provider, guards, injection patterns, prompts
│  │  ├─ api/           deps, serializers, routers/{health,auth,chat,admin}.py
│  │  ├─ knowledge/     uploads, extraction, cleaning, chunking, FTS5 indexing, retrieval
│  │  ├─ middleware/    request context, body-size limit, CSRF, security headers
│  │  ├─ models/        SQLAlchemy models (users, sessions, conversations, documents, audit, rate limits)
│  │  ├─ repositories/  all SQL, owner-scoped, parameterised
│  │  ├─ schemas/       Pydantic request/response models
│  │  ├─ security/      passwords, sessions, CSRF, cookies
│  │  ├─ services/      auth, chat, knowledge, rate limiting
│  │  ├─ config.py      Pydantic Settings (fails fast on unsafe configuration)
│  │  ├─ db.py          engine/session factory, SQLite PRAGMAs
│  │  ├─ errors.py      typed error hierarchy + one JSON error envelope
│  │  └─ main.py        app factory, lifespan, middleware stack, route table
│  └─ tests/            unit (66) + integration (16) + security (48) = 130 tests
├─ frontend/
│  └─ src/              App, api client, AuthPanel, ChatPanel, AdminPanel, ErrorBoundary, styles
├─ knowledge_base/documents/   11 fictional Acme Support documents (TXT/MD/PDF)
├─ scripts/            operational + verification tooling (see §6)
├─ docs/               SECURITY.md, VERIFICATION_REPORT.md, PROJECT_STATE.md
└─ pyproject.toml      ruff / mypy / pytest / coverage / bandit configuration
```

Runtime data (`storage/`, `logs/`, `*.db`, `node_modules/`, `dist/`) is git-ignored and never
served: uploads live outside any directory the web server exposes.

## 3. Quick start (Windows / PowerShell)

```powershell
Set-Location 'c:\Users\abdul\OneDrive\Desktop\cline test\AI CUSTOMER SUPPORT'

# 1. Environment + dependencies (Python >= 3.11)
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt

# 2. Configuration. `.env` is optional in development (a random secret key is generated);
#    in any non-development environment SECRET_KEY is REQUIRED and must not be a placeholder.
Copy-Item .env.example .env

# 3. Database + knowledge base + first administrator
.\.venv\Scripts\python.exe scripts\seed_knowledge.py            # imports knowledge_base/documents (idempotent)
$env:ACME_ADMIN_PASSWORD = 'choose-a-strong-passphrase'          # or omit to be prompted
.\.venv\Scripts\python.exe scripts\create_admin.py --email admin@example.com
Remove-Item Env:\ACME_ADMIN_PASSWORD

# 4. Run the backend (loopback only)
Set-Location backend; ..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 5. Run the frontend (new terminal; Vite proxies /api -> 127.0.0.1:8000)
Set-Location frontend; npm ci; npm run dev
```

Open <http://127.0.0.1:5173>. Interactive API docs are available at
<http://127.0.0.1:8000/docs> in development only — they are disabled when `APP_ENV` is not a
development-like value.

Closing note: `scripts/create_admin.py` never has a default password and enforces the same
password policy customers face.

---

## 4. Configuration

All settings come from environment variables (optionally via `.env`); `.env.example` documents
every one. Invalid or unsafe values abort startup with a clear message rather than failing later.

| Group | Key settings |
| --- | --- |
| App | `APP_ENV`, `APP_NAME`, `HOST`, `PORT` |
| AI | `AI_PROVIDER` (`mock` is the only accepted value) |
| Database | `DATABASE_URL` (relative SQLite paths resolve against the project root), `SQL_ECHO` |
| Secrets | `SECRET_KEY` (required outside development), `CANARY_TOKEN` (optional) |
| Network | `ALLOWED_ORIGINS`, `ALLOWED_HOSTS`, `TRUSTED_PROXIES`, `ENABLE_DOCS_IN_DEV`, `SECURITY_HEADERS_ENABLED` |
| Sessions/cookies | `SESSION_EXPIRE_MINUTES`, `COOKIE_NAME`, `COOKIE_SECURE`, `COOKIE_SAMESITE`, `CSRF_HEADER_NAME` |
| Passwords | `PASSWORD_MIN_LENGTH`, `PASSWORD_MAX_LENGTH`, `LOGIN_MAX_FAILED_ATTEMPTS`, `LOGIN_LOCKOUT_MINUTES` |
| Knowledge base | `UPLOAD_DIR`, `MAX_UPLOAD_MB`, `MAX_PDF_PAGES`, `MAX_EXTRACTED_CHARS`, `MAX_DOCUMENTS`, `CHUNK_SIZE_CHARS`, `CHUNK_OVERLAP_CHARS` |
| Retrieval | `RETRIEVAL_TOP_K`, `RETRIEVAL_MIN_SCORE`, `MAX_CONTEXT_CHARS`, `RETRIEVAL_TIMEOUT_SECONDS` |
| AI limits | `MAX_MESSAGE_CHARS`, `MAX_RESPONSE_CHARS`, `MAX_HISTORY_MESSAGES`, `MAX_CONVERSATIONS_PER_USER` |
| Rate limits | `RATE_LIMIT_*`, `MAX_REQUEST_BODY_BYTES` |
| Logging | `LOG_LEVEL`, `LOG_DIR`, `LOG_JSON`, rotation settings |

`HOST` is intentionally loopback-only (`127.0.0.1`); production deployments must terminate TLS
and reverse-proxy to the loopback socket (see `docs/SECURITY.md`).

---

## 5. API surface (21 endpoints)

| Method | Path | Access |
| --- | --- | --- |
| GET | `/health` | public |
| POST | `/api/auth/register` | public (rate limited, anti-enumeration response) |
| POST | `/api/auth/login` | public (rate limited, lockout after repeated failures) |
| GET | `/api/auth/csrf` | public (issues the pre-auth CSRF pair) |
| GET | `/api/auth/session` | authenticated |
| POST | `/api/auth/logout` | authenticated |
| POST | `/api/auth/password` | authenticated |
| DELETE | `/api/auth/account` | authenticated |
| POST | `/api/chat/conversations` | owner |
| GET | `/api/chat/conversations` | owner |
| GET | `/api/chat/conversations/{conversation_id}` | owner |
| DELETE | `/api/chat/conversations/{conversation_id}` | owner |
| POST | `/api/chat/messages` | owner |
| PUT | `/api/chat/messages/{message_id}/feedback` | owner |
| GET | `/api/admin/stats` | admin |
| GET | `/api/admin/documents` | admin |
| POST | `/api/admin/documents` | admin (multipart upload) |
| GET | `/api/admin/documents/{document_id}` | admin |
| POST | `/api/admin/documents/{document_id}/reindex` | admin |
| DELETE | `/api/admin/documents/{document_id}` | admin |
| GET | `/api/admin/audit` | admin |

Cross-owner access to a conversation, message or feedback row returns **404**, not 403, so the
API never confirms that someone else's identifier exists.

## 6. Knowledge base and scripts

`knowledge_base/documents/` holds 11 fictional Acme Support articles (Products, Pricing, Refunds,
Shipping, Account, Troubleshooting, Contact, FAQ, Plans, Security, Billing Guidelines) in TXT, MD
and PDF form — 25 indexed chunks in total. `scripts/seed_knowledge.py` imports them idempotently
(re-running it does not duplicate documents). `backend/tests/fixtures/poisoned_document.md` is a
deliberately hostile fixture used to prove indirect prompt-injection detection; it is never seeded.

| Script | Purpose |
| --- | --- |
| `seed_knowledge.py` | Import `knowledge_base/documents/` into the knowledge base (idempotent) |
| `create_admin.py` | Create/promote an administrator (`ACME_ADMIN_PASSWORD` or interactive prompt) |
| `smoke_test.py` | End-to-end API smoke test on a throwaway database (36 checks) |
| `run_tests.py` | Run the pytest + quality-gate suite and write a report under `logs/` |
| `make_seed_pdf.py` | Deterministically regenerate the seed PDF |
| `check_headers.py`, `check_filename_rules.py`, `check_non_ascii.py` | Focused assertions for security headers, upload filename rules and suspicious Unicode |
| `fix_homoglyphs.py`, `show_bytes.py`, `debug_guard.py`, `dump_response_headers.py`, `dump_signatures.py`, `snippet.py` | Development/inspection helpers |

---

## 7. Quality gates

Run from the project root with the virtual environment active:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests --cov=backend/app --cov-report=term   # 130 passed, 82% coverage
.\.venv\Scripts\python.exe scripts\smoke_test.py                                         # 36 checks, all passed
.\.venv\Scripts\ruff.exe check backend scripts                                           # All checks passed
.\.venv\Scripts\ruff.exe format --check backend/app backend/tests scripts                # 81 files already formatted
.\.venv\Scripts\mypy.exe                                                                 # Success: no issues in 76 files
.\.venv\Scripts\python.exe scripts\check_non_ascii.py                                    # homoglyphs / invisible characters (exit 0)
.\.venv\Scripts\python.exe scripts\check_headers.py                                      # security-header ASCII literals
.\.venv\Scripts\python.exe scripts\check_filename_rules.py                               # hostile upload filenames rejected
.\.venv\Scripts\bandit.exe -r backend/app -c pyproject.toml -q                           # 0 high, 7 medium/2 low (all audited false positives)
.\.venv\Scripts\pip-audit.exe -r requirements.txt                                        # no known vulnerabilities
.\.venv\Scripts\detect-secrets.exe scan --all-files --baseline .secrets.baseline          # 16 known, reviewed findings

Set-Location frontend
npm ci; npm run build; npm test; npm run lint; npm audit                                 # build OK, 2 tests, lint clean, 0 vulnerabilities
```

Measured results, including the disposition of every static-analysis finding, are recorded in
[`docs/VERIFICATION_REPORT.md`](docs/VERIFICATION_REPORT.md). The security design and its limits
are described in [`docs/SECURITY.md`](docs/SECURITY.md).

---

## 8. Security posture (summary)

* Argon2id password hashing; password policy enforced for customers and admins alike.
* Opaque 256-bit session tokens stored **hashed**; logout/password change revoke server-side.
* HttpOnly + SameSite cookies; `Secure` configurable for local HTTP development.
* CSRF double-submit token (`X-CSRF-Token`) required on every unsafe method.
* Strict security headers (CSP with `default-src 'none'`, `nosniff`, `DENY` framing, no-referrer,
  restrictive `Permissions-Policy`); API responses marked `Cache-Control: no-store`.
* Typed request models, body-size limits, upload magic-byte + extension + size + page-count checks,
  stored filenames replaced by random UUIDs outside the served tree.
* SQLite-backed rate limiting per user, per IP and per route class, with `Retry-After` on 429.
* Structured JSON logs with redaction; secrets and canary tokens never logged.
* Prompt-injection defence in depth: input guard, knowledge-base chunk screening (indirect
  injection), system-prompt isolation and an output guard with canary/secret/path redaction.
* Anti-enumeration registration: a duplicate signup and a fresh signup produce byte-identical
  responses (the UI additionally shows one static, generic message for both).

---

## 9. Known limitations

* **Mock AI only.** Answers are deterministic templates over retrieved text — the system is a
  grounded retrieval assistant, not a generative model. `AI_PROVIDER` accepts only `mock`.
* **Single node.** SQLite (WAL) plus in-process rate-limit counters suit one process; horizontal
  scaling would require a shared database and a shared limiter.
* **No TLS.** The app binds to loopback and expects a TLS-terminating reverse proxy in production
  (see the hardening checklist in `docs/SECURITY.md`).
* **Retrieval quality is lexical.** FTS5/BM25 with a coverage floor favours precision over recall;
  synonyms that never appear in the corpus are not matched (and are refused rather than guessed).
* The admin UI's upload flow was verified in a real browser via Playwright's file-input API, since
  the MCP upload helper only accepts files inside its own permitted roots.

---

## 10. License / provenance

All knowledge-base content is fictional and written for this project. No external AI service,
model download, or paid API is used at build time or runtime.


