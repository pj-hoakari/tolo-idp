# tolo-idp better-auth test harness

Local-only test client for OIDC login and Token Exchange against tolo-idp.

This directory is committed only on the stacked review branch `feature/better-auth-test-harness` (draft PR, not intended to merge into `main`). For day-to-day work, keep it out of git via `.git/info/exclude`.

## Prerequisites

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

`.env.local` defaults to `TOLO_IDP_URL=http://localhost:8080`.

## docker-compose.dev.native

```bash
docker compose -f docker-compose.dev.native.yaml up --build
```

Update `.env.local`:

```env
TOLO_IDP_URL=http://localhost:18080
NEXT_PUBLIC_TOLO_IDP_URL=http://localhost:18080
```

## Run this app

```bash
cd local/better-auth-test
npm install
npx auth@latest migrate
npm run dev
```

Open http://localhost:3000 and use:

- username: `user-123`
- password: `password`
- tenant: `tenant-a`

## Phase 1: OIDC login

1. Click **Login to IdP**
2. Click **Continue with OIDC**

After OIDC completes, open http://localhost:3000/dashboard.

## Phase 2: Token Exchange

The dashboard loads a `tenant_access` preview and exposes Step 3.

1. Confirm the preview shows `token_use: tenant_access` and `scope` includes `events.read`
2. Exchange with:
   - Event ID: `event-1`
   - Scope: `events.read`
   - Audience: `backend-api`
3. Expect `event_access` claims with `event_id: event-1`

### Scope changes require re-OIDC

If OIDC scopes were expanded after you first signed in, sign out and run Step 2 again. Token Exchange requires the stored `tenant_access` token to already include the requested event scope.

### Expected failure case

- Event ID `event-3` with `user-123` should fail because relation-stub has no event role for that user.

### Debug with curl

After signing in through the browser, reuse the session cookie:

```bash
curl -s http://localhost:3000/api/tolo-idp/tenant-token \
  -H 'Cookie: better-auth.session_token=...'

curl -s -X POST http://localhost:3000/api/token-exchange \
  -H 'Cookie: better-auth.session_token=...' \
  -H 'Content-Type: application/json' \
  -d '{"eventId":"event-1","scope":"events.read"}'
```
