# tolo-idp better-auth test harness

Local-only test client for OIDC login, Token Exchange, refresh token rotation, and revocation against tolo-idp.

## Prerequisites

- Node.js 24
- tolo-idp running with seed enabled
- relation-stub running (for tenant membership)

## bootRun

```bash
# terminal 1:
docker compose -f docker-compose.dev.jvm.yaml up -d
# terminal 2:
cd /path/to/tolo-idp
TOLO_IDP_SEED_ENABLED=true \
TOLO_IDP_RATE_LIMIT_ENABLED=false \
TOLO_IDP_ISSUER=http://localhost:8080 \
./gradlew bootRun --args='--spring.profiles.active=dev.jvm' --rerun-tasks
```

Set both `TOLO_IDP_URL` and `NEXT_PUBLIC_TOLO_IDP_URL` to `http://localhost:8080` in `.env.local` for this configuration.

## docker-compose.dev.native

```bash
docker compose -f docker-compose.dev.native.yaml up -d --build
```

The example environment uses `http://localhost:18080` for both IdP URLs. The Better Auth callback is `http://localhost:3000/api/auth/callback/tolo-idp`, which is registered for the development client `client-123`.

## Run this app

```bash
cd local/better-auth-test
cp .env.local.example .env.local # First run only; keep existing settings.
npm ci
npx auth@latest migrate
npm run dev
```

Open http://localhost:3000 and sign in with:

- username: `user-123`
- password: `password`

The harness selects tenant `tenant-a` with the `resource` authorization parameter in `src/lib/auth.ts`.

The example credentials are for local development only. `.env.local` and `sqlite.db` are excluded from Git.

## Phase 1: OIDC login

1. Click **Sign in with tolo-idp**.
2. tolo-idp redirects to http://localhost:3000/login with a login challenge. Enter the credentials and click **Log in**.
3. The login page sends the credentials and the challenge to `/api/login`, then opens `/oauth2/authorize?challenge=...`. tolo-idp resumes the original authorization request and redirects to the Better Auth callback.

Better Auth completes the Authorization Code flow with PKCE and verifies the ID token. After OIDC completes, open http://localhost:3000/dashboard. When tolo-idp rejects a challenge, it redirects to http://localhost:3000/auth/error.

## Phase 2: Token Exchange

The dashboard loads a `tenant_access` preview and exposes Step 3.

1. Confirm the preview shows `token_use: tenant_access` and `scope` includes `events.read`.
2. Exchange with Event ID `event-1`, Scope `events.read`, and Audience `backend-api`.
3. Expect `event_access` claims with `event_id: event-1`.

### Scope changes require re-OIDC

If OIDC scopes were expanded after you first signed in, sign out and run Step 2 again. Token Exchange requires the stored `tenant_access` token to already include the requested event scope. Update requested scopes in `src/lib/auth.ts`; do not request `offline_access`, which tolo-idp does not support.

### Expected failure case

Event ID `event-3` with `user-123` should fail because relation-stub has no event role for that user.

## Phase 3: Refresh and revoke

1. Click **4. Refresh tokens**. Expect `refreshTokenRotated: true`, `refreshTokenSaved: true`, `idTokenIssued: true`, and a new `jti`. Better Auth's standard refresh API updates and saves the tokens.
2. Click **End IdP session**, then refresh again. Refresh should still succeed because the Better Auth session and refresh token remain valid.
3. Click **5. Revoke refresh token**. Expect `revoked: true` and `accessTokenActive: false`.
4. Refresh again. Expect the operation to fail because the refresh token has been revoked.
5. Click **Sign out of Better Auth and sign in again** to start over.

Better Auth sign-out, IdP session termination, and refresh token revocation are separate operations in this harness. The revoked token remains stored locally so that the next refresh attempt demonstrates rejection. Refresh tokens and client secrets stay on the server; the controls return status and decoded claims only.

## Type checking

```bash
npm run typecheck
```

Use the browser steps above to check the harness manually.

## Debug with curl

After signing in through the browser, reuse the session cookie:

```bash
curl -s http://localhost:3000/api/tolo-idp/tenant-token \
  -H 'Cookie: better-auth.session_token=...'

curl -s -X POST http://localhost:3000/api/token-exchange \
  -H 'Cookie: better-auth.session_token=...' \
  -H 'Content-Type: application/json' \
  -d '{"eventId":"event-1","scope":"events.read"}'
```
