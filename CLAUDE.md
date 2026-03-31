# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A minimalist, zero-dependency OpenID Connect (OIDC) Authorization Server built with Bun. It is intentionally educational — not for production use. All state is in-memory and lost on restart.

## Commands

```bash
bun run dev       # Start dev server with hot-reload (port 3000)
bun run build     # Bundle to ./dist
bun run start     # Run production build
bun test          # Run full test suite with coverage
```

There is no linter configured.

## Architecture

Everything lives in `src/`:

- **`index.ts`** — Main Bun HTTP server. Handles all 5 endpoints, in-memory storage (clients, users, auth sessions), and all crypto helpers.
- **`keys.ts`** — Generates RSA-2048 key pair on first run, persists to `keys.json` (gitignored).
- **`index.test.ts`** — Bun test suite. Spawns the server as a subprocess per test suite; tests run against the live server.

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | Public JWK Set for token verification |
| `GET/POST /authorize` | Serves login form / handles credential submission |
| `POST /token` | Exchanges authorization code for access + id tokens |
| `GET /userinfo` | Returns user claims from Bearer token |

### OAuth 2.1 / PKCE Flow

`/authorize` → login form → POST credentials → auth code → `/token` (with PKCE S256 verifier) → JWT tokens → `/userinfo`

### In-memory state (in `index.ts`)

- **clients** Map: default `sample-client` / `sample-secret`
- **users** Map: default `testuser` / `password123` (PBKDF2+salt hashed)
- **authSessions** Map: maps auth codes to session data; entries expire after 15 minutes and are deleted after token exchange

### Crypto (all via Node.js `crypto`, no external libs)

- JWT signing/verification: RS256
- Password hashing: PBKDF2-SHA512 with random salt, timing-safe compare
- PKCE: SHA-256 code challenge (S256 method)
- Auth codes: 16-byte random hex

## Git Workflow

This project follows **GitHub Flow**. Never commit directly to `main`. Always create a branch and merge via Pull Request.

Branch names should be flat and descriptive — no folder prefixes (e.g., `update-readme-refresh-token`, not `docs/update-readme` or `feat/refresh-token`).

## Test Notes

Tests in `index.test.ts` spawn the server via `Bun.spawn`. Each `describe` block starts a fresh server instance. To run a single test file:

```bash
bun test src/index.test.ts
```

Test output is written to `junit.xml`; coverage to LCOV format.
