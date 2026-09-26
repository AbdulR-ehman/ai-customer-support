# SECURITY — Acme Support AI

This document describes the security controls that are actually implemented, the reasoning behind
them, the results of the static/dependency analysis runs, and the residual risks a deployment must
handle itself. It is a design + evidence document, not marketing: known gaps are listed in §12
rather than omitted.

---

## 1. Scope and threat model

**Assets**

| Asset | Why it matters |
| --- | --- |
| Customer accounts and passwords | Account takeover, credential-stuffing reuse elsewhere |
| Conversation content | Private support history (potentially personal data) |
| Knowledge base | Integrity of the answers the assistant gives |
| Audit log | Non-repudiation of administrative actions |
| `SECRET_KEY` / session records | Forgery of CSRF tokens; session theft |

**Assumed attacker capabilities**

* Can register an account and drive the full customer API at will.
* Can send arbitrary HTTP (malformed JSON, oversized bodies, unexpected headers, hostile `Host`,
  forged `X-Forwarded-For`).
* Can upload documents as an administrator (or social-engineer one) — so upload content must be
  treated as untrusted input to the AI layer.
* Cannot read server memory, the filesystem or the database, and cannot modify server code.
* Cannot break TLS where it is deployed (TLS termination is out of scope here — see §11 and §12).

**Trust boundaries**

1. Browser ↔ Vite dev server / reverse proxy (untrusted input).
2. HTTP layer ↔ application (validated by Pydantic schemas, body limits, CSRF, TrustedHost).
3. Uploaded document content ↔ AI prompt (untrusted text; treated as *data*, never as instructions).
4. Application ↔ SQLite (all statements parameterised; FTS5 SQL built only from constants).

---

## 2. Authentication and password storage

* **Hashing**: Argon2id via `argon2-cffi`. Plaintext passwords are never logged or stored, and are
  dropped as early as possible in the bootstrap scripts (`del password`).
* **Policy**: `PASSWORD_MIN_LENGTH` (default 10) / `PASSWORD_MAX_LENGTH` (default 128), a
  common/weak-password blocklist, and rejection of passwords containing the account's email
  local-part. The same policy applies to administrators — there is no admin exemption.
* **No default credentials**: `scripts/create_admin.py` requires `ACME_ADMIN_PASSWORD` or an
  interactive prompt; no fallback password exists in the code.
* **Login lockout**: after `LOGIN_MAX_FAILED_ATTEMPTS` (default 5) failures the account is locked for
  `LOGIN_LOCKOUT_MINUTES` (default 15) and the event is audited as `user.lockout`.
* **Failed-login records**: stored (normalised email, IP, success flag) only to drive lockout and
  anomaly reporting; purged after 30 days by the maintenance helpers.
* **Enumeration resistance**: login returns one generic failure message whether or not the address
  exists; registration returns a byte-identical response for a fresh and a duplicate signup, and the
  UI shows a single static, generic notice for both.

## 3. Session management

* Opaque **256-bit** tokens from `secrets.token_urlsafe(32)` — no JWT, so nothing is trusted from the
  client except an unguessable random string.
* Only the **SHA-256 hash** of the token is persisted, so a database read does not yield usable sessions.
* Sessions are **server-side rows**: logout, password change and account deletion set `revoked_at`,
  which takes effect immediately (no "valid until expiry" window).
* Every login creates a **new** session row, and any session presented during login is revoked first —
  defeating session fixation.
* Lifetime is bounded by `SESSION_EXPIRE_MINUTES` (default 120); expired and long-revoked rows are
  purged by the maintenance helpers.
* Cookies are `HttpOnly`, `SameSite` (`lax` by default) and path-scoped; `Secure` is configurable
  because local HTTP development cannot set it. `COOKIE_SAMESITE=none` is rejected unless
  `COOKIE_SECURE=true`, enforced at configuration load.

## 4. CSRF

State-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) must present an `X-CSRF-Token` header that
matches a **signed** value held in a cookie:

* authenticated requests — `HMAC-SHA256(secret, session_id)`;
* pre-authentication requests (login/register) — `HMAC-SHA256(secret, preauth_nonce)`, where the
  nonce is issued by `GET /api/auth/csrf` into the `acme_csrf` cookie.

Comparison is constant-time (`hmac.compare_digest`), needs no database access, and unsafe requests
arriving with no CSRF context at all are rejected outright. Because the session cookie is
`HttpOnly`, a cross-site script cannot read the value it would need to forge the header.

## 5. Authorisation and identifier handling

* Two roles exist (`customer`, `admin`). The role is **never** accepted from a request body:
  registration always creates a customer, and only an existing admin or the bootstrap script can
  create an admin.
* Route protection is enforced by dependencies (`require_user`, `require_admin`), and a test asserts
  that every registered route is either in the explicit public allow-list or carries an auth dependency.
* Public identifiers are UUID4 (unguessable).
* Customer-facing lookups are **owner-scoped in the repository layer**: another user's resource is
  simply not found, so the API answers **404 rather than 403** and never confirms that someone else's
  identifier exists.
* Admin-only operations are audited with actor, target and request id.

## 6. Input validation, uploads and resource limits

* **Schemas**: every request body is a Pydantic v2 model with explicit types, length bounds and
  validators; unexpected fields are rejected. Message length, feedback comment length and
  conversation/message counts are capped by settings.
* **Body size**: middleware rejects oversized bodies before routing (`MAX_REQUEST_BODY_BYTES`,
  default 1 MiB — deliberately above `MAX_UPLOAD_MB` plus multipart overhead).
* **Upload validation** (defence in depth; all checks must pass):
  * extension allow-list `.txt`, `.md`, `.pdf`;
  * **magic bytes** must agree with the extension — a `.pdf` not beginning with `%PDF-` is rejected
    (`unsupported_media_type`);
  * size limit `MAX_UPLOAD_MB` (default 5 MB);
  * PDF page count ≤ `MAX_PDF_PAGES` (default 200), extracted text ≤ `MAX_EXTRACTED_CHARS`
    (default 500 000), plus a wall-clock extraction deadline, so a "PDF bomb" cannot exhaust CPU or memory;
  * encrypted PDFs are refused; embedded JavaScript/attachments are never executed (pypdf reads text
    operators only);
  * filenames are sanitised and the on-disk name is replaced by a random UUID.
* **Storage**: uploads live under `storage/uploads/`, outside any directory the web server serves, so
  an uploaded file can never be fetched by URL.
* **De-duplication**: content is hashed, so re-uploading identical bytes returns the existing document
  instead of creating a duplicate (and cannot be used to shadow an existing one).

## 7. Prompt-injection and output controls

The AI layer treats every string — user message *and* knowledge-base text — as untrusted data.

**Input path**

1. `normalize_for_guard` applies Unicode NFKC folding, homoglyph mapping and zero-width-character
   stripping before matching, so `Ｉｇｎｏｒｅ all previous instructions` and
   `I\u200bgnore all previous instructions` are recognised as the same attack as plain ASCII.
2. The pattern table in `app/ai/injection_patterns.py` classifies attempts (instruction override,
   prompt extraction, secret extraction, role manipulation, policy bypass, delimiter escape, encoded
   payload) and matches multilingual variants.
3. A blocked message short-circuits to a fixed refusal **before** the provider is called, and the
   event is audited as `guard.injection_blocked`.

**Indirect (document-borne) injection**

Ingested chunks are screened for instruction-like content; suspicious chunks are flagged and excluded
from the retrieval context. `backend/tests/fixtures/poisoned_document.md` exists to prove this path and
is never part of the seeded knowledge base.

**Output guard**

Provider output passes through `scan_output`, which redacts canary tokens, detected secret-like strings
and absolute filesystem paths, enforces `MAX_RESPONSE_CHARS`, and drops anything resembling a
system-prompt leak. The system prompt is isolated from user-visible text at the template level.

## 8. Rate limiting and abuse control

* SQLite-backed **fixed-window** counters with a single atomic upsert, so concurrent requests cannot
  double-spend a slot.
* Separate limits per route class and identity: chat per minute and per day, login per minute,
  registration per hour, uploads per hour, plus a global per-minute ceiling.
* `429` responses include `Retry-After` (exposed through CORS) and are audited as `rate_limit.blocked`.
* Client IPs come from the socket unless `TRUSTED_PROXIES` is configured, so `X-Forwarded-For` cannot
  be spoofed by a direct client by default.

## 9. Transport, headers and browser hardening

Applied to every response (JSON, HTML and errors alike):

| Header | Value |
| --- | --- |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; worker-src 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=(), usb=()` |
| `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` | `same-origin` |
| `X-Permitted-Cross-Domain-Policies` | `none` |
| `Cache-Control` | `no-store` on API responses |

`Server` / `X-Powered-By` are stripped. `TrustedHostMiddleware` rejects unexpected `Host` headers, and
CORS is restricted to `ALLOWED_ORIGINS` with credentials enabled. HSTS is deliberately **not** sent by
default because the app runs over loopback HTTP; enable it at the TLS terminator (§11).

### The one exception: `/docs` and `/redoc` (development only)

The interactive docs are the only routes that receive a relaxed `Content-Security-Policy`. Swagger UI
and ReDoc are shipped as CDN bundles, execute an inline initializer and (ReDoc) spawn a worker, so the
strict `script-src 'self'` above renders a blank page. Those two paths get:

```
default-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; font-src 'self' https://fonts.gstatic.com; worker-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
```

Every added origin is the minimum each tool needs: `cdn.jsdelivr.net` (Swagger/ReDoc JS + CSS),
`fonts.googleapis.com` and `fonts.gstatic.com` (ReDoc webfonts), `fastapi.tiangolo.com` (Swagger
favicon), `cdn.redoc.ly` (ReDoc logo) and `blob:` (ReDoc search worker). `default-src 'none'`,
`connect-src 'self'`, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'` and
`object-src 'none'` still apply, so the exception cannot reach the API, cookies, `localStorage` or the
SPA.

The override is applied **per response** in `SecurityHeadersMiddleware`, matching exactly `/docs`,
`/redoc` and their sub-paths after trailing-slash normalisation. Everything else - `/health`,
`/openapi.json`, every `/api/*` route, all error responses and the built frontend - keeps the strict
policy in the table above. Both halves are pinned by
`backend/tests/security/test_security.py::test_api_docs` (relaxed on the two docs routes, strict on
`/health`). In production the exception cannot be reached at all: with `ENABLE_DOCS_IN_DEV=false` the
docs routes are never registered and answer `404` (§11, item 5).

## 10. Logging, privacy and secrets

* Structured logging (JSON by default) with a redaction filter: `Authorization`, `Cookie`, `Set-Cookie`,
  passwords, tokens and `SECRET_KEY` values never reach the log stream.
* Request correlation via `X-Request-ID`; every error response carries the same id so a user-visible
  failure can be matched to a log line without exposing internals.
* Error responses use one envelope (`error.code`, `error.message`, `request_id`) and never echo stack
  traces, SQL, or filesystem paths.
* The startup summary logs the *shape* of the configuration (environment, provider, host, port, whether
  docs are enabled) and never a secret value.
* Conversation content is user data: it is stored to provide history, is only readable by its owner,
  and `RETENTION_DAYS` (0 = disabled) plus the maintenance helpers support a retention policy.
* Secret material: `SECRET_KEY` is required outside development and placeholder values (`changeme`,
  empty, etc.) are rejected at startup. `CANARY_TOKEN` is generated randomly per process when unset.
  `.env` is git-ignored; only `.env.example` is committed.

## 11. Production hardening checklist

1. Set `APP_ENV` to a non-development value and provide a strong, unique `SECRET_KEY`.
2. Terminate TLS in front of the app and enable HSTS at that layer; set `COOKIE_SECURE=true` (and only
   then consider `COOKIE_SAMESITE=none`).
3. Keep the app bound to `127.0.0.1`; expose it only through the reverse proxy.
4. Set `ALLOWED_ORIGINS` and `ALLOWED_HOSTS` to the real public names; set `TRUSTED_PROXIES` to the
   proxy CIDRs so client IPs (and therefore rate limits) are accurate.
5. Leave `ENABLE_DOCS_IN_DEV=false` so `/docs`, `/redoc` and `/openapi.json` are not served.
6. Run migrations/creation at deploy time, keep `storage/` and the SQLite file on a private volume, and
   back them up (the WAL files too).
7. Ship `logs/` to a central, access-controlled sink; alert on `rate_limit.blocked`,
   `guard.injection_blocked` and `user.lockout` spikes.
8. Re-run the quality gates (§12) in CI on every change, including `pip-audit`, `npm audit` and `bandit`.

## 12. Static analysis and dependency results (measured)

Run on 2026-09-25 with the pinned toolchain in `requirements-dev.txt`
(ruff 0.16.8, mypy 2.3.1, bandit 1.9.4, pip-audit 2.10.1, detect-secrets 1.5.0) plus npm 11.17.0.

| Tool | Command | Result |
| --- | --- | --- |
| ruff (lint) | `ruff check backend scripts` | **All checks passed** (105 initial findings reviewed: 43 auto-fixed, 62 resolved by fixing 2 real defects — see below — and by documented, targeted suppressions) |
| ruff (format) | `ruff format --check backend/app backend/tests scripts` | **81 files already formatted** |
| mypy | `mypy` (strict-ish: `disallow_untyped_defs`) | **Success: no issues found in 76 source files** |
| bandit | `bandit -r backend/app -c pyproject.toml` | 0 high, 7 medium, 2 low — all reviewed below |
| pip-audit | `pip-audit -r requirements.txt` | **No known vulnerabilities found** |
| detect-secrets | `detect-secrets scan --all-files --baseline .secrets.baseline` | 17 findings, all reviewed below (`.secrets.baseline` is kept locally for diffing and is git-ignored — `.gitignore` line 46 — so each run is diffed against this machine's baseline) |
| npm audit | `npm audit` | **0 vulnerabilities** (after upgrading vitest 3.2.7 → 5.0.2) |

**Project-specific checks (in addition to the generic tooling above)**

None of the generic tools above can see a homoglyph, so three focused scripts cover the failure
modes that matter most here. All three exit 0 on the current tree.

| Check | Command | What it proves | Result |
| --- | --- | --- | --- |
| Homoglyph / invisible characters | `python scripts\check_non_ascii.py` | Scans `backend/app`, `frontend/src`, `scripts` — **string literals only** (AST-derived, so comments and docstrings are exempt as prose). Flags ASCII look-alikes (Cyrillic/Greek/fullwidth/mathematical, and anything NFKC-folding to a single ASCII alphanumeric) and `Cf`/`Cc` format characters (zero-width joiners, bidi overrides, stray controls). A Cyrillic "о" inside `"nosniff"` is invisible in an editor but is a different byte on the wire and silently disables the header; this is the gate that prevents that class of typo. The four modules that exist in order to *describe* these characters (`ai/injection_patterns.py`, `ai/normalization.py`, `fix_homoglyphs.py`, the scanner itself) are allow-listed by design. `backend/tests` is excluded by default because it deliberately contains hostile payloads — pass paths explicitly to audit it. Writes `logs/non_ascii_report.txt`. | **85 files, 0 suspicious lines** |
| Security-header literals | `python scripts\check_headers.py` | Every one of the 8 configured header values is plain ASCII, so no header can be nullified by a look-alike character; 4 of them are additionally pinned to their exact expected string. | **Clean** (8 headers, 4 exact) |
| Upload filename rules | `python scripts\check_filename_rules.py` | The upload validator rejects traversal (`../`, `..\`, percent-encoded), absolute paths, UNC paths and the Windows device namespace, drive letters, NTFS alternate data streams (`:`), reserved device names (`CON`, `nul`), NUL bytes, home-relative paths and double extensions — while normalising benign names such as `trailing. .txt`. | **18 rejected / 4 accepted, 0 problems** |

**Real defects found and fixed during this review**

* `backend/app/models/user.py` — `Mapped[list[Conversation]]` / `Mapped[list[Feedback]]` referenced
  forward types that were never imported (ruff `F821`, mypy `name-defined`). Fixed with a
  `TYPE_CHECKING` import so the runtime model registry is untouched.
* `backend/app/api/routers/auth.py` — an unpacked `token` was unused and the register handler held the
  same return in both branches; simplified to a single unconditional generic response (the
  anti-enumeration guarantee is unchanged and still exercised by tests).
* `backend/app/db.py` and `backend/app/api/routers/chat.py` — two `assert`s in production paths were
  replaced with explicit checks (bandit `B101`), because `python -O` strips asserts and the invariant
  would silently disappear.
* `backend/app/knowledge/extraction.py` — a bare `except … continue` around per-page PDF text
  extraction now logs a debug line before skipping the page (bandit `S112`).
* SQLAlchemy `rowcount` accesses were typed with `cast(CursorResult[Any], …)` so mypy verifies the
  delete/update result handling instead of silently ignoring it.

**Accepted false positives (with reasoning)**

| Finding | Location | Disposition |
| --- | --- | --- |
| `B608` ×7 — "possible SQL injection" | `knowledge/indexing.py`, `knowledge/retrieval.py` | The FTS5 DDL/DML is built from module-level constants (`FTS_TABLE`, `TOKENIZER`); every value is a bound parameter (`:chunk_id`, `:query`, `:limit`). No user data is ever interpolated — verified by reading each statement. Ruff `S608` is suppressed for exactly these two files with the reason recorded in `pyproject.toml`. |
| `B105` ×2 — "hardcoded password" | `ai/injection_patterns.py:18` (`"secret_extraction"`), `models/audit.py:24` (`"user.password_change"`) | These are category/audit *labels*, not credentials. Suppressed per file with a comment in `pyproject.toml`. |
| `detect-secrets`: `Hex High Entropy String` ×3 | `security/passwords.py:64-66` | Entries of the weak-password **blocklist** (`abcd12345`, `a1b2c3d4e5`, `abc123456`) — the opposite of a secret. |
| `detect-secrets`: `Secret Keyword` ×13 | `README.md:92`, `models/audit.py:24`, `tests/conftest.py`, `tests/integration/test_api_flows.py`, `scripts/{create_admin,smoke_test,dump_response_headers}.py` | Disposable, project-local test/bootstrap credentials, env-var *names* (`ACME_ADMIN_PASSWORD`) and one documentation example (`$env:ACME_ADMIN_PASSWORD = 'choose-a-strong-passphrase'` in the quick start). None is a real credential; production secrets are supplied via environment variables and are never committed. `.secrets.baseline` records them so any *new* finding fails the diff. |
| `detect-secrets`: `Base64 High Entropy String` ×1 | `tests/conftest.py:132` | The same disposable `secret_key` literal already listed above, flagged a second time by the base64-entropy plugin; it configures the test app only. |

## 13. Residual risk and explicitly out-of-scope

* **TLS termination** is not implemented; the app speaks HTTP on loopback and relies on a reverse proxy.
  Until TLS is in place, cookies travel without the `Secure` attribute (documented configuration trade-off
  for local development).
* **Rate limiting is fixed-window and per-process.** It is deliberately simple: it blunts brute force and
  casual abuse but is not a defence against a distributed attacker with many source IPs, and it does not
  coordinate across multiple app processes.
* **CSRF tokens are bound to the session cookie value**, so a token is invalid after logout/login by
  design; the frontend re-fetches the pre-auth pair on demand.
* **No 2FA / email verification.** Registration does not prove control of the email address; it also
  cannot be used to enumerate accounts.
* **Uploaded content is stored in plaintext** on disk (outside the served tree). At-rest encryption is not
  implemented; rely on volume/disk encryption in production.
* **The mock provider cannot be compromised or prompt-hijacked** in the way a hosted LLM could be; if a
  real provider is added later, the input/output guards must be re-validated against it (`AI_PROVIDER`
  currently refuses any value other than `mock`, which fails safe).
* **Automatic dependency scanning is not scheduled** in this environment; the commands in §12 are run
  manually and should be wired into CI.




