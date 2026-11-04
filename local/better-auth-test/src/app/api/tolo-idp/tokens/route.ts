import { NextResponse } from "next/server";
import { APIError } from "better-auth/api";
import { decryptOAuthToken } from "better-auth/oauth2";
import { auth } from "@/lib/auth";
import { requireBetterAuthSession, ToloIdpSessionError } from "@/lib/tolo-idp-session";
import { decodeJwtPayload, getToloIdpConfig, TOLO_IDP_PROVIDER_ID } from "@/lib/tolo-idp";

// OAuth token material stays on the server. Only status and decoded claims leave this route.
export async function POST(request: Request) {
  const expectedOrigin = new URL(process.env.BETTER_AUTH_URL ?? "http://localhost:3000").origin;
  if (request.headers.get("origin") !== expectedOrigin) {
    return NextResponse.json({ error: "origin_not_allowed" }, { status: 403 });
  }
  const body: unknown = await request.json().catch(() => null);
  const action = body && typeof body === "object" && "action" in body ? body.action : null;
  if (action !== "refresh" && action !== "revoke") {
    return NextResponse.json({ error: "action must be refresh or revoke" }, { status: 400 });
  }
  try {
    const session = await requireBetterAuthSession();
    const context = await auth.$context;
    const accounts = await context.internalAdapter.findAccounts(session.user.id);
    const account = accounts.find((candidate) => candidate.providerId === TOLO_IDP_PROVIDER_ID);
    if (!account?.refreshToken) {
      throw new ToloIdpSessionError(400, "Refresh token not found. Complete OIDC sign-in again.");
    }
    const previousRefresh = await decryptOAuthToken(account.refreshToken, context);
    if (action === "refresh") {
      // Better Auth handles refresh and saves the rotated token for the next request.
      const tokens = await auth.api.refreshToken({
        headers: request.headers,
        body: { accountId: account.id },
      });
      if (!tokens.accessToken) throw new ToloIdpSessionError(502, "Refresh response did not include an access token.");
      const saved = (await context.internalAdapter.findAccounts(session.user.id)).find((item) => item.id === account.id);
      const persistedRefresh = saved?.refreshToken ? await decryptOAuthToken(saved.refreshToken, context) : null;
      return NextResponse.json({
        action,
        refreshTokenPresent: Boolean(persistedRefresh),
        refreshTokenRotated: previousRefresh !== persistedRefresh,
        refreshTokenSaved: persistedRefresh === tokens.refreshToken,
        idTokenIssued: Boolean(tokens.idToken),
        accessClaims: decodeJwtPayload(tokens.accessToken),
      }, { headers: { "Cache-Control": "no-store" } });
    }
    const config = getToloIdpConfig();
    const clientParams = { client_id: config.clientId, client_secret: config.clientSecret };
    const response = await fetch(`${config.baseUrl}/oauth2/revoke`, {
      method: "POST",
      body: new URLSearchParams({ ...clientParams, token: previousRefresh, token_type_hint: "refresh_token" }),
      cache: "no-store",
    });
    if (!response.ok) {
      return NextResponse.json({ error: "revoke_failed" }, { status: response.status });
    }
    const accessToken = account.accessToken ? await decryptOAuthToken(account.accessToken, context) : null;
    let accessTokenActive: boolean | null = null;
    if (accessToken) {
      const introspection = await fetch(`${config.baseUrl}/oauth2/introspect`, {
        method: "POST",
        body: new URLSearchParams({
          client_id: config.gatewayClientId,
          client_secret: config.gatewayClientSecret,
          token: accessToken,
        }),
        cache: "no-store",
      });
      if (introspection.ok) accessTokenActive = (await introspection.json()).active === true;
    }
    // Keep the revoked token in the local harness to demonstrate the subsequent refresh rejection.
    return NextResponse.json({ action, revoked: true, accessTokenActive }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof ToloIdpSessionError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    if (error instanceof APIError) {
      return NextResponse.json({ error: error.body?.code ?? "auth_failed", error_description: error.body?.message }, { status: error.statusCode });
    }
    // Avoid dumping request data, credentials or provider responses into Next's error log.
    console.error("tolo-idp token operation failed", { action });
    return NextResponse.json({ error: "token_operation_failed" }, { status: 502 });
  }
}
