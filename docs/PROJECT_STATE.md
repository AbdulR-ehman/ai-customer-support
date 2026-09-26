# PROJECT STATE — Acme Support AI

> Living state file. Updated at the end of every phase and after any major fix.
> **Never store secrets here.**

_Last updated: Phase 20 — documentation reconciliation + focused-check hardening (2026-09-25)_

## Current phase

**COMPLETE.** The backend, frontend, knowledge base, automated suites, security tooling and both
browser journeys are implemented and verified. All quality gates pass; the remaining items are
improvements, not blockers (see "Open issues" below).

## Environment

| Item | Value |
| --- | --- |
| OS | Windows 11 |
| Shell | PowerShell 5.1 (`powershell.exe`) |
| Project root | `c:\Users\abdul\OneDrive\Desktop\AI CUSTOMER SUPPORT` |
| Python | 3.14.3 in `./.venv` (project declares `>= 3.11`) |
| Node.js / npm | v24.19.0 / 11.17.0 — frontend dependencies pinned exactly and locked (`package-lock.json`) |
| Playwright | MCP browser session (Chromium) used for live verification; no separate browser download |
| Git | This directory is **not** a Git repository; nothing was pushed or deployed |

All work and server bindings are confined to the project directory and loopback addresses
(`127.0.0.1:8000` backend, `127.0.0.1:5173` frontend). No system-level changes were made.

## Architectural decisions

- **Stack**: FastAPI + Pydantic v2 + SQLAlchemy 2.x + SQLite; React 19 + Vite 7 + TypeScript
  (dev proxy → same-origin API, HttpOnly cookies).
- **AI**: `AIProvider` abstraction; `MockAIProvider` is the only implementation and the only accepted
  `AI_PROVIDER` value (anything else refuses to start). Deterministic, offline, template-based.
- **Retrieval**: SQLite **FTS5 + BM25** (`bm25()` ranking), parameterised queries only, sanitised FTS
  query text, term-coverage floor (`MIN_TERM_COVERAGE = 0.3`) so unrelated questions are refused
  instead of answered. No embeddings, no model downloads.
- **Auth**: opaque 256-bit session tokens stored **hashed** (SHA-256) in a `sessions` table → real
  server-side revocation. Argon2id password hashing. No JWT.
- **CSRF**: signed double-submit token (`HMAC(secret, identity)`) sent as `X-CSRF-Token` on every
  unsafe method; pre-auth nonce cookie for login/registration.
- **IDs**: UUID4 public identifiers; cross-owner access returns 404 (not 403) so nothing is confirmed.
- **Ports**: loopback only, never `0.0.0.0`.
- **Rate limiting**: SQLite-backed fixed-window counters (per user / per IP / per route class) with
  `Retry-After` on 429.
- **Uploads**: stored in `storage/uploads/` (outside any served directory), random UUID storage names,
  magic-byte + extension + size + page-count checks, content-hash de-duplication.
- **Config**: `pydantic-settings` reading `.env`; relative SQLite URLs resolve against the project root;
  unsafe/placeholder secrets abort startup outside development.

## Verified commands and current results

```powershell
Set-Location 'c:\Users\abdul\OneDrive\Desktop\AI CUSTOMER SUPPORT'
```

| Gate | Command | Result (2026-09-25) |
| --- | --- | --- |
| Backend tests + coverage | `python -m pytest backend/tests --cov=backend/app --cov-report=term` | **130 passed**, 82% coverage |
| API smoke test | `python scripts\smoke_test.py` | **36 checks passed**, 0 failed |
| Lint | `ruff check backend scripts` | **All checks passed** |
| Format | `ruff format --check backend/app backend/tests scripts` | **81 files already formatted** |
| Typing | `mypy` | **Success: no issues in 76 files** |
| SAST | `bandit -r backend/app -c pyproject.toml` | 0 high, 7 medium, 2 low (all audited false positives) |
| Dependency audit (Python) | `pip-audit -r requirements.txt` | **No known vulnerabilities** |
| Secret scan | `detect-secrets scan --all-files --baseline .secrets.baseline` | 16 reviewed false positives |
| Homoglyph / invisible characters | `python scripts\check_non_ascii.py` | **85 files scanned, 0 suspicious lines** (string literals only; allow-lists the 4 modules that describe such characters; `backend/tests` opt-in) |
| Security-header literals | `python scripts\check_headers.py` | **All 8 headers clean ASCII**, 4 pinned to exact values |
| Upload filename rules | `python scripts\check_filename_rules.py` | **18 hostile names rejected, 4 legitimate accepted, 0 problems** |
| Frontend | `npm ci && npm run build && npm test && npm run lint && npm audit` | build OK, 2 tests passed, lint clean, **0 vulnerabilities** |
| Live browser | Playwright against `uvicorn` + `npm run dev` | customer + admin journeys verified end-to-end |

## Completed phases

- [x] **Phase 1** — workspace inspected, OS/shell detected, project folder identified.
- [x] **Phase 2** — `.venv` created; pinned `requirements.txt` / `requirements-dev.txt`.
- [x] **Phase 3** — `config.py`, redacting structured logging, global error handlers.
- [x] **Phase 4** — SQLAlchemy models, repositories, SQLite PRAGMAs (FK on, WAL).
- [x] **Phase 5** — Argon2id passwords, hashed opaque sessions, CSRF, lockout,
      `require_user` / `require_admin`.
- [x] **Phase 6** — upload validation, extraction (TXT/MD/PDF), cleaning, chunking, FTS5 indexing,
      idempotent re-index and delete.
- [x] **Phase 7** — BM25 retrieval with sanitised FTS queries and the term-coverage floor.
- [x] **Phase 8** — `AIProvider` + `MockAIProvider`, direct/indirect injection guards, output guard
      with canary/secret/path redaction.
- [x] **Phase 9** — chat, conversation and feedback APIs plus the full API layer and smoke test.
- [x] **Phase 10** — 11 fictional knowledge documents (TXT/MD/PDF) + idempotent seeding script.
- [x] **Phase 11** — `scripts/create_admin.py` (getpass or `ACME_ADMIN_PASSWORD`, no default).
- [x] **Phase 12** — pytest unit + integration + security suites (130 tests, 82% coverage).
- [x] **Phase 13** — React/Vite/TypeScript frontend (customer + admin, no `VITE_*` secrets, no
      `dangerouslySetInnerHTML`); production build, ESLint and Vitest green.
- [x] **Phase 14** — security tool review (ruff/mypy/bandit/pip-audit/detect-secrets/npm audit) with
      every finding triaged in `docs/SECURITY.md` §12.
- [x] **Phase 15** — live browser verification: customer journey (register/login/chat/sources/
      refusals/feedback/history/logout) and admin journey (dashboard/upload/re-index/delete/audit).
- [x] **Phase 16** — documentation set: `README.md`, `docs/SECURITY.md`,
      `docs/VERIFICATION_REPORT.md`, and this file.
- [x] **Phase 17** — anti-enumeration registration hardening: a fresh and a duplicate signup now
      return byte-identical responses (no existence oracle), backed by a dedicated test.
- [x] **Phase 18** — dependency remediation: Vite → 7.3.6 and Vitest → 5.0.2, clearing the
      remaining `npm audit` advisories; quality-gate defects fixed (see B-13 … B-20).
- [x] **Phase 19** — the over-broad whole-file Unicode scan was replaced by
      `scripts/check_non_ascii.py`, which inspects **string literals only** (AST-derived) for
      homoglyphs and invisible format characters, allow-lists the four modules that exist to
      describe such characters, and treats `backend/tests` as opt-in because it deliberately
      contains hostile payloads. All four documents were rewritten against the measured results.
- [x] **Phase 20** — documentation reconciliation: the three focused checks
      (`check_non_ascii.py`, `check_headers.py`, `check_filename_rules.py`) are now documented in
      the README quality-gate block and in `SECURITY.md` §12 / `VERIFICATION_REPORT.md` §8 /
      `PROJECT_STATE.md`. Two claims were found to overstate what the scripts actually enforced,
      and the **scripts were corrected** rather than the prose (B-21, B-22).

## Verification status (current, measured)

| Check | Result |
| --- | --- |
| `pytest backend/tests --cov=backend/app` | **130 passed** (unit 66 · security 48 · integration 16), **82%** statement coverage |
| `scripts\smoke_test.py` | **36 checks passed** — health, headers, request id, CSRF, register/login/logout, session invalidation, grounded chat with sources, feedback, history, refusals, admin stats/list/upload/dedup/reindex/disguised-PDF-reject/delete/audit |
| Backend import / route table | OK — `app.main:app`, **21 endpoints** across the health/auth/chat/admin routers |
| Live customer journey | Verified in Chromium: grounded answer with 2 cited sources, both refusal paths, persisted feedback, history restored after reload |
| Live admin journey | Verified in Chromium: 11 docs/25 chunks → upload → 12/26 → re-index → delete → 11/25, with a complete audit trail |
| Frontend build / tests / lint | Clean build (34 modules), **2 Vitest tests passed**, **0 lint findings** |
| `npm audit` | **0 vulnerabilities** (vitest upgraded 3.2.7 → 5.0.2, vite 7.3.6) |
| Static analysis | ruff clean · mypy clean (76 files) · bandit 0 high · pip-audit clean · detect-secrets triaged |

## Bugs found and fixed

| ID | Issue | Fix |
| --- | --- | --- |
| B-4 | `api/deps.py` imported non-existent `AuthorizationError` | use `PermissionDeniedError` |
| B-5 | `api/deps.py` signed the pre-auth CSRF token with the raw nonce | sign with `preauth_identity(nonce)` |
| B-6 | `scan_output` called `.splitlines()` on a tuple | accept `str \| Sequence[str]` |
| B-7 | `MAX_REQUEST_BODY_BYTES` default (1 MB) < `MAX_UPLOAD_MB` (5 MB) | default raised to 6 MB |
| B-8 | `schemas/chat.py` used `field_validator` before importing it | moved import to the top |
| B-9 | Conversation detail default `limit=200` exceeded the 100 cap (422) | default lowered to 50 |
| B-10 | Follow-up retrieval retry let an unrelated question inherit an earlier answer | retry only for short, low-term questions |
| B-11 | A single incidental keyword match counted as grounded | added `MIN_TERM_COVERAGE = 0.3` |
| B-12 | `total_conversations` missing for the admin dashboard | added owner-agnostic count |
| B-13 | `models/user.py` declared `Mapped[list[Conversation]]` / `Mapped[list[Feedback]]` without importing those types (ruff `F821`, mypy `name-defined`) | added a `TYPE_CHECKING` import (runtime model registry unchanged) |
| B-14 | `api/routers/auth.py` unpacked an unused CSRF `token` and held an unreachable duplicate return branch | consume the pair as `nonce, _token` and return the single generic response |
| B-15 | Production `assert`s in `db.py` and `api/routers/chat.py` would vanish under `python -O` (bandit `B101`) | replaced with explicit runtime checks / typed errors |
| B-16 | Bare `except … continue` swallowed per-page PDF extraction failures (bandit `S112`) | log a debug line before skipping the page |
| B-17 | mypy reported 28 errors (SQLAlchemy `rowcount`, `FromClause.delete`, cookie kwargs typing, unused ignores) | `cast(CursorResult[Any], …)`, `delete(Model)` statements, `Literal` cookie SameSite type, explicit cookie kwargs, removed stale ignores |
| B-18 | `npm audit` reported 2 moderate advisories via `@vitest/mocker` (`GHSA-82fw-gwwq-j7x9`) | upgraded vitest to 5.0.2 (Node 24 + Vite 7 compatible) → 0 vulnerabilities |
| B-19 | `/favicon.ico` 404 in the browser console | added an inline SVG favicon to `index.html` (no extra request) |
| B-20 | `ruff format --check` failed on 46 files (formatting drift) | ran `ruff format`; all 81 files now formatted, tests re-run green |
| B-21 | `scripts/check_headers.py` only compared 4 of the 8 configured headers and only ASCII-screened the CSP, so its "all header values are clean ASCII" message was not backed by the code — `Permissions-Policy`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` were never inspected | iterate over all of `SECURITY_HEADERS` for non-ASCII, keeping the 4 exact-string assertions |
| B-22 | `scripts/check_filename_rules.py` did not exercise UNC paths, the Windows device namespace, encoded-dot traversal or an allowlisted-prefix double extension, yet the documentation claimed that coverage | added `\\\\server\share\evil.txt`, `//server/share/evil.txt`, `\\?\C:\evil.txt`, `..%2e%2e/evil.txt`, `invoice.pdf.php`; moved `trailing. .txt` to the accept list (it is *normalised* to `trailing.txt`, not rejected) → 18 rejected / 4 accepted |

## Open issues / known limitations

| ID | Issue | Status |
| --- | --- | --- |
| K-1 | No CI pipeline: the gates are run manually | documented in `docs/SECURITY.md` §11 and `docs/VERIFICATION_REPORT.md` §9 |
| K-2 | No committed Playwright spec (browser verification was interactive) | accepted; the API smoke test provides regression cover |
| K-3 | `MockAIProvider` is deliberately non-generative (grounded templates only) | by design |
| K-4 | SQLite + in-process rate limits mean a single-node deployment | by design; see README §9 |
| K-5 | No TLS/HSTS inside the app; a reverse proxy is required | documented hardening checklist |
| K-6 | Local `storage/app.db` holds throwaway verification accounts | git-ignored; delete the file for a clean slate |
| K-7 | PowerShell 5.1 sometimes drops output / reports exit code 1 for tools that write to stderr | workaround: redirect to `logs/*.txt` and read the file |

## Next steps (optional improvements)

1. Wire the "Verified commands" block into a CI workflow, including `pip-audit`, `npm audit` and `bandit`.
2. Convert the interactive browser verification into a committed Playwright spec (admin upload,
   re-index, delete; customer chat, refusals, feedback, history).
3. Add code-splitting to the frontend bundle and run an accessibility scan (axe) in CI.
4. Tune FTS5 (`prefix`/`trigram` tokenizers) or add a small synonym map to improve recall while keeping
   the grounded-refusal behaviour intact.
5. Add a scheduled retention/cleanup job using `RETENTION_DAYS` and the existing purge helpers.


