# MCP Prompt Validator

A remote (**Streamable-HTTP**) **Model Context Protocol** server that exposes a
**multi-category prompt validator** as MCP tools, with:

- **Role-Based Access Control (RBAC)** enforced in middleware,
- a **dynamic, per-role skill/tool surface** ("dynamic skill supplier"), and
- **per-user permanent tokens** (long-lived API keys) for authentication.

Built on **FastMCP** (the standalone `fastmcp` package), SQLAlchemy 2.0 async +
PostgreSQL, and ML-grade validators (Presidio, a prompt-injection classifier,
zero-shot banned-topics, Detoxify).

> This README doubles as the design document. Sections follow the TSI spec
> template: Overview, Requirements, Technical Approach, Assumptions, Out of
> Scope, Roadmap, Effort Estimation.

---

## 1. Overview

An MCP client (an agent/IDE/service) connects over HTTP and presents a permanent
bearer token. The server validates the token against the database, resolves the
caller's role, and advertises **only** the tools that role may use. When the
client calls `validate_prompt`, the prompt is run through a parallel pipeline of
category detectors and a single structured **verdict** is returned
(`allow` / `flag` / `redact` / `block`) with per-category findings.

```
                          ┌───────────────────────────────────────────────┐
  MCP client (HTTP)  ───►  │  FastMCP server (Streamable HTTP, /mcp)         │
  Authorization:          │                                                 │
  Bearer <jwt>            │  ① Verify token (JWT default, or opaque)        │
                          │       └─ JWTVerifier + jti denylist → AccessToken│
                          │            (scopes = role + permitted tags)      │
                          │  ② RBACMiddleware                               │
                          │       ├─ on_list_tools → filter by tags  ◄── dynamic skill supply
                          │       └─ on_call_tool  → allow / ToolError      │
                          │  ③ Tools                                        │
                          │       ├─ validate_prompt / _prompts / _structured
                          │       ├─ redact_prompt · whoami · list_skills   │
                          │       └─ admin: grant/revoke tag, users, tokens │
                          │  ④ ValidationRunner  → parallel validators      │
                          │       PII · secrets · injection · banned-topics │
                          │       · schema/length · toxicity  → Aggregator  │
                          └───────────────────────────────────────────────┘
                                          │
                    PostgreSQL: roles · role_tag_permissions · users
                                · api_tokens (hashed) · audit_logs
```

---

## 2. Requirements

**Functional**

1. Expose prompt validation as MCP tools over Streamable HTTP.
2. Validate a prompt across multiple policy categories: **PII, secrets,
   prompt-injection, banned topics, length/format/schema, toxicity**.
3. Return a **structured verdict** per call: overall `passed`, recommended
   `action`, `max_severity`, and per-category findings with reasons.
4. Provide **PII/secret redaction** (`redact_prompt`) and **batch** and
   **schema-constrained** validation variants.
5. Authenticate every request with a **per-user permanent bearer token**;
   reject unknown, revoked, or expired tokens.
6. Enforce **RBAC**: each role is permitted a set of tool **tags**; callers only
   **see** and can only **call** the tools their role permits.
7. Support **dynamic skill supply**: an admin can grant/revoke a role's tags at
   runtime (DB-driven) and the change applies on the next request — no redeploy.
8. **Prompt templates** (Jinja2), scoped **per-user** or **global** (a global
   template is usable by all users). Exposed to clients via MCP tools; managed in
   the dashboard. Users only see their own + global templates.
9. **Admin dashboard** (Jinja2, interactive/animated) to view/set dynamic skills
   per role, inspect users, and create/manage prompt templates.
10. **Audit** validation runs and access decisions.

**Non-functional**

11. Fail-safe: a broken/slow detector must not crash a request (per-validator
    timeout → HIGH finding by default).
12. Horizontally scalable (stateless HTTP option); secrets never logged; tokens
    stored only as hashes.

---

## 3. Technical Approach

### 3.1 Framework choice — `fastmcp` (standalone)

We use the **standalone `fastmcp` package**, not the `FastMCP` bundled in the
`mcp` SDK. Auth providers, the middleware pipeline, and per-role tool visibility
are first-class there; the bundled fork lacks them. FastMCP is built on top of
the official SDK, so protocol compatibility is unaffected.

### 3.2 Authentication — two modes (`MPV_AUTH_MODE`)

The MCP spec models the server as an **OAuth 2.1 Resource Server** whose mandated
job is to **validate** inbound bearer tokens. This server can also **issue** the
credentials it validates. Two interchangeable modes:

**`jwt` (default) — the server issues + verifies signed JWTs.**
- `auth/jwt_issuer.py` mints a JWT per user via `mpv-issue-jwt` / the
  `issue_user_jwt` admin tool / the bootstrap seed. Claims carry identity
  (`sub`, `username`, `role`) and authorisation (`scope` = role + permitted
  tags), so **access is enforced per-user** with no extra lookups.
- `auth/jwt_verifier.py` → **`RevocableJWTVerifier`** wraps FastMCP's
  `JWTVerifier` (validates signature, `iss`, `aud`, `exp`) and adds a **`jti`
  denylist** check so an issued token can be revoked before it expires.
- **RS256** by default: a private key signs, the public key verifies. Dev
  auto-generates and persists a keypair in `MPV_JWT_KEYS_DIR`; production mounts
  its own. **HS256** shared-secret is a config switch (`MPV_JWT_ALGORITHM=HS256`
  + `MPV_JWT_HS_SECRET`).
- Issued grants are tracked in `jwt_grants` (jti, user, expiry, revoked) for
  listing/auditing. The denylist is cached in-memory (TTL `MPV_REVOCATION_CACHE_TTL`)
  so the per-request revocation check is a set lookup, not a DB hit.
- Trade-off: JWT claims are baked in at issue time, so a **permission change**
  (grant/revoke role tag) applies to a user only when their token is re-issued or
  expires; **revocation** is immediate via the denylist. Use finite TTLs.

**`opaque` — the server issues + verifies opaque permanent keys.**
- `auth/verifier.py` → **`DatabaseTokenVerifier`**: hash the presented token →
  single indexed DB lookup → reject if unknown/revoked/expired/inactive → return
  an `AccessToken` whose `scopes` encode role + tags. Tokens are `mpv_` + 256
  bits; only the **SHA-256 hash** is stored (constant-time compare).
- Permissions loaded **per request**, so both revocation *and* permission changes
  are immediate — at the cost of a DB lookup each request.
- Optionally wrapped in `RemoteAuthProvider` for RFC 9728 discovery.

Either way the resulting `AccessToken.scopes` drive the **same** RBAC middleware,
so the rest of the system is auth-mode-agnostic.

### 3.3 RBAC + dynamic skill supply

`rbac/middleware.py` → **`RBACMiddleware`** enforces at **both** layers from one
source of truth (`skills/registry.py::TOOL_TAGS`):

- `on_list_tools` filters the advertised list so a role only *sees* its tools.
- `on_call_tool` raises `ToolError` for any tool the role may not call — the
  backstop, because list-filtering alone is only discovery-hiding.

Each tool is tagged (`register_skill(..., tags={"validator"})`). A role's
permitted tags live in `role_tag_permissions`; the verifier turns them into
`tag:*` scopes. Admin roles bypass tag checks. Admins can `grant_role_tag` /
`revoke_role_tag` at runtime — this is the dynamic skill supplier.

### 3.4 Validation pipeline

- `validation/contracts.py` — `Severity`, `Finding`, `Verdict` (pydantic v2).
- `validation/base.py` — `Validator` ABC + registry; add a category = add a class.
- `validation/runner.py` — runs validators **concurrently** (`asyncio.gather`),
  each ML call offloaded via `asyncio.to_thread`, each under a per-validator
  timeout; failures become fail-safe findings.
- `validation/policy.py` — `Aggregator` maps findings → one action using
  precedence `block > redact > flag > allow`.
- `validation/validators/*` — one module per category:

  | Category       | Detector (default)                               | On fail |
  |----------------|--------------------------------------------------|---------|
  | secrets        | curated regex set (dependency-free)              | block   |
  | schema/length  | pydantic + jsonschema + tiktoken                 | block   |
  | pii            | Microsoft Presidio (+ anonymizer for redaction)  | redact  |
  | injection      | HF classifier (Llama-Prompt-Guard-2) + heuristics| block   |
  | banned_topics  | zero-shot NLI (bart-large-mnli) over a topic list| block   |
  | toxicity       | Detoxify (+ better-profanity fast gate)          | flag    |

  Heavy models lazy-load and **disable themselves gracefully** if the `[ml]`
  extra is absent, so the lightweight validators still run in dev/CI.

### 3.4a Prompt templates (per-user + global)

- `db/models.py::PromptTemplate` — `name`, `body` (Jinja2), `owner_user_id`
  (nullable), `is_global`, `enabled`. A user may use a template if it is **theirs
  or global**, and enabled.
- `prompts/render.py` renders bodies in a **`SandboxedEnvironment`** with
  `StrictUndefined` (user templates can't reach unsafe attributes; missing vars
  error clearly). `prompts/service.py` is the CRUD + visibility layer.
- MCP tools (tag `public`): `list_prompt_templates` and `render_prompt_template`
  — both filtered to the caller's own + global templates.

### 3.4b Admin dashboard

A Jinja2 + Starlette dashboard mounted on the **same server** as `/mcp` (default
at `/admin`), served via `mcp.http_app()` mounted under a parent Starlette app
(lifespan propagated). Login takes an **admin** bearer credential (JWT or opaque),
verified by the same token verifier; a signed session cookie
(`MPV_DASHBOARD_SECRET`) holds the admin session. Pages:

- **Skills & Roles** — animated tag toggles that grant/revoke each role's skills
  (the dynamic skill supplier), via `POST /admin/api/role-tag`.
- **Users** — each user's role and the skills currently available to them; add users.
- **Prompts** — table of templates with per-row **Global** and **Enabled**
  toggles, a create modal (with the **Global** switch), and delete — all via JSON
  APIs with toast feedback and CSS animations.

The dashboard and MCP admin tools share `rbac/service.py` and `prompts/service.py`,
so they never diverge.

### 3.5 Data model

`roles` · `role_tag_permissions` · `users` · `api_tokens` (hashed) ·
`audit_logs`. See `db/models.py`; migrations in `migrations/`.

### 3.6 Project layout

```
src/mcp_prompt_validator/
  config.py            settings (pydantic-settings, MPV_ env prefix)
  server.py            assembly + entrypoint (mpv-server)
  auth/                tokens, scopes, _compat, DatabaseTokenVerifier,
                       jwt_keys, jwt_issuer, jwt_verifier, jwt_service, revocation
  rbac/                middleware (RBAC hooks) + service (shared RBAC ops)
  skills/registry.py   register_skill + TOOL_TAGS + tool_permitted
  validation/          contracts, base, runner, policy, validators/*
  prompts/             render (sandboxed Jinja2) + service (CRUD/visibility)
  tools/               validation_tools, admin_tools, prompt_tools
  web/                 app (ASGI compose), dashboard (routes), templates/*.html
  db/                  base (async engine/session), models
  scripts/             seed, mint_token, issue_jwt (console entrypoints)
migrations/            alembic env + initial migration
tests/                 SQLite-based suite (ML/MCP tests skip if absent)
examples/client_demo.py
Dockerfile · docker-compose.yml · Makefile
```

### 3.7 Key libraries

`fastmcp`, `mcp`, `sqlalchemy[asyncio]`, `asyncpg`, `alembic`, `pydantic(-settings)`,
`uvicorn`; validators: `presidio-analyzer/-anonymizer`, `spacy`, `transformers`,
`torch`, `detoxify`, `better-profanity`, `detect-secrets`, `jsonschema`, `tiktoken`.

### 3.8 Deployment

`docker-compose` runs Postgres + the app. The entrypoint applies Alembic
migrations, optionally seeds, then serves on `:8000/mcp`. For serverless/scaled
deploys, run stateless behind sticky-session-free load balancing and raise proxy
idle timeouts (Streamable HTTP holds connections open).

---

## 4. Quickstart

```bash
docker compose up --build -d
```

On first boot (`MPV_SEED=true`) the logs print a **bootstrap admin JWT** (or an
opaque token in `opaque` mode) — copy it. Then point an MCP client at
`http://localhost:8000/mcp` with header `Authorization: Bearer <token>`.

Create a scoped (non-admin) user, then issue a JWT for it:

```bash
docker compose exec app mpv-issue-jwt admin --name cli
```

To make a *new* user you call the admin `create_user` tool over MCP (using the
admin token), then issue its JWT:

```bash
docker compose exec app mpv-issue-jwt analyst-bot --name ci --ttl 86400
```

Revoke an issued JWT by its `jti` (admin tool `revoke_jwt`, or it expires at TTL).
In `opaque` mode, mint keys with `mpv-mint-token <user>` instead.

Try the demo client (works with a JWT or an opaque token):

```bash
MPV_TOKEN=<paste-token> python examples/client_demo.py
```

**Admin dashboard:** open <http://localhost:8000/admin>, and sign in by pasting the
bootstrap **admin** credential from the logs. From there you can add users, and
create both **prompt templates** and **skill documents**. Both are scoped the
same way: pick an **Owner** to keep it private to one user, or flip the
**Global** switch to serve it to everyone. Set `MPV_DASHBOARD_SECRET` in
production.

Agents consume skills through two tools — `list_skills` (name + description
only, for cheap discovery) then `get_skill(name)` for the full Markdown body.
Both are scoped to the caller's token: a user sees only their own skills plus
global ones, and `get_skill` on a skill owned by someone else returns
"not found" rather than confirming it exists.

Local (no Docker) dev install + tests:

```bash
pip install -e ".[dev,ml]"
pytest -q
```

The test suite runs on SQLite and skips ML/MCP-dependent tests when those
packages are absent, so `pip install -e ".[dev]"` + `pytest -q` is a fast green.

---

## 5. Security Considerations

- **Permanent tokens trade convenience for risk.** Mitigations built in: store
  only SHA-256 hashes, per-user scoping, instant revocation (`revoked_at`),
  optional `expires_at`, HTTPS-only in production, secrets never echoed in
  findings or logs.
- **Audience validation.** The spec requires rejecting tokens not issued for
  this server. `resource_server_url` is set on the AccessToken; enforce/verify it
  at the edge (or use a signed-JWT verifier with `audience=`) — see Roadmap.
- **Defense in depth.** RBAC is enforced on both `on_list_tools` and
  `on_call_tool`; never rely on list-filtering alone.
- **Injection detectors over-flag.** The classifier is paired with explainable
  heuristics and tunable thresholds; measure false positives before hard-blocking.
- **Fail-safe by default** (`MPV_VALIDATOR_FAIL_MODE=safe`): a broken detector
  blocks rather than silently passes.

---

## 6. Assumptions

1. Tokens are minted out-of-band by this app (admin tool / CLI); no interactive
   OAuth flow is required.
2. One role per user is sufficient for v1.
3. English-first detection; multilingual tuning is future work.
4. Postgres is the production datastore; SQLite is dev/test only.
5. Clients send the token on every request as `Authorization: Bearer`.

---

## 7. Out of Scope (v1)

- Interactive OAuth / IdP login flows and token issuance UI.
- Per-tool (finer than per-tag) permissions and multi-role users.
- Output/response validation (this validates *input* prompts).
- Rate limiting / quota (add via FastMCP middleware later).
- Model fine-tuning; a management dashboard.

---

## 8. Phased Roadmap

1. **Core (this repo):** server, auth, RBAC, validator pipeline, seed/CLI, tests, Docker.
2. **Hardening:** signed-JWT token option (`JWTVerifier`, audience), rate-limit
   middleware, structured JSON logging, Prometheus metrics.
3. **Accuracy:** replace/augment detectors (LLM-Guard scanners, multilingual
   models), per-tenant policy profiles, threshold tuning from audit data.
4. **Ops:** admin dashboard, key rotation workflow, horizontal-scale load test.

---

## 9. Effort Estimation

Ranges in hours; assumes one mid/senior Python engineer familiar with MCP.

| Phase        | Work                                                        | Estimate |
|--------------|-------------------------------------------------------------|----------|
| Analysis     | Finalise policy matrix, thresholds, role/tag model          | 4–6 hrs  |
| Development   | Auth + RBAC + pipeline + tools + migrations (core repo)    | 24–32 hrs|
| Development   | ML validator integration + tuning (Presidio/injection/tox) | 12–18 hrs|
| Testing      | Unit + integration + a live MCP-client smoke test           | 10–14 hrs|
| Deployment   | Docker/compose, CI, staging config, model-cache sizing      | 6–10 hrs |
| **Total**    |                                                             | **56–80 hrs** |

**Risks / clarifications:** (a) gated HF models (Llama Prompt Guard) need license
acceptance + `HF_TOKEN`; (b) ML image size/cold-start (torch + spaCy + weights)
may push toward a warm pool or ONNX (`speedtoxify`); (c) false-positive tuning on
the injection/banned-topics detectors needs real sample data; (d) if a signed-JWT
token model is preferred over opaque keys, swap `DatabaseTokenVerifier` for
`JWTVerifier` (audience/issuer) — budget +4–6 hrs.

---

## 10. Version notes (verified against current docs)

- **`fastmcp` 3.x.** Uses only the stable subset: `FastMCP`, `add_middleware`,
  `Middleware`/`on_list_tools`/`on_call_tool`, `get_access_token`, custom
  `TokenVerifier`. Two import spots (`TokenVerifier`, `AccessToken`) are resolved
  defensively in `auth/_compat.py`.
- **`BearerAuthProvider` was removed** (FastMCP 2.14). We deliberately do **not**
  use it; opaque permanent keys use a `TokenVerifier` subclass, and signed JWTs
  would use `JWTVerifier`.
- **Per-component `enable()/disable()` and `@tool(enabled=False)` are
  deprecated/removed** in FastMCP 3.0 — those are global/feature-flag switches
  anyway. Per-**user** visibility is done in middleware (the stable path).
- **Transport string is `"http"`** for FastMCP (`"streamable-http"` in the bare
  `mcp` SDK); the ASGI app method is `http_app()` (vs `streamable_http_app()`).
