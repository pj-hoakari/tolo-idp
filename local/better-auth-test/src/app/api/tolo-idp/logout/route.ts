import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { requireBetterAuthSession, ToloIdpSessionError } from "@/lib/tolo-idp-session";
import { getToloIdpConfig, TOLO_IDP_PROVIDER_ID } from "@/lib/tolo-idp";

export async function POST(request: Request) {
  const appUrl = process.env.BETTER_AUTH_URL ?? "http://localhost:3000";
  if (request.headers.get("origin") !== new URL(appUrl).origin) {
    return NextResponse.json({ error: "origin_not_allowed" }, { status: 403 });
  }
  try {
    const session = await requireBetterAuthSession();
    const context = await auth.$context;
    const accounts = await context.internalAdapter.findAccounts(session.user.id);
    const idToken = accounts.find((account) => account.providerId === TOLO_IDP_PROVIDER_ID)?.idToken;
    if (!idToken) {
      throw new ToloIdpSessionError(400, "ID token not found. Complete OIDC sign-in again.");
    }
    const discovery = await fetch(`${getToloIdpConfig().baseUrl}/.well-known/openid-configuration`, { cache: "no-store" });
    const { end_session_endpoint: endSession } = await discovery.json();
    if (typeof endSession !== "string") {
      return NextResponse.json({ error: "end_session_endpoint_missing" }, { status: 502 });
    }
    const target = new URL(endSession);
    target.searchParams.set("id_token_hint", idToken);
    target.searchParams.set("post_logout_redirect_uri", new URL("/auth/logged-out", appUrl).href);
    target.searchParams.set("state", "better-auth-test");
    return NextResponse.redirect(target, 303);
  } catch (error) {
    if (error instanceof ToloIdpSessionError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    console.error("tolo-idp logout failed");
    return NextResponse.json({ error: "logout_failed" }, { status: 502 });
  }
}
