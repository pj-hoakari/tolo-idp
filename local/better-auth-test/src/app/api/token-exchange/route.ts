import { NextResponse } from "next/server";
import {
  decodeJwtPayload,
  DEFAULT_AUDIENCE,
  DEFAULT_EVENT_SCOPE,
  exchangeForEventAccess,
  getClaimString,
  getClaimStringArray,
  TokenExchangeRequestError,
} from "@/lib/tolo-idp";
import {
  ensureTenantAccessScopes,
  getTenantAccessTokenInfo,
  ToloIdpSessionError,
} from "@/lib/tolo-idp-session";

type TokenExchangeRequestBody = {
  eventId?: string;
  scope?: string;
  audience?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as TokenExchangeRequestBody;
    const eventId = body.eventId?.trim();
    if (!eventId) {
      return NextResponse.json({ error: "eventId is required" }, { status: 400 });
    }

    const scope = body.scope?.trim() || DEFAULT_EVENT_SCOPE;
    const audience = body.audience?.trim() || DEFAULT_AUDIENCE;

    const tenantToken = await getTenantAccessTokenInfo();
    ensureTenantAccessScopes(tenantToken.claims, scope);

    const exchangeResult = await exchangeForEventAccess({
      subjectToken: tenantToken.accessToken,
      tenantId: tenantToken.tenantId,
      eventId,
      audience,
      scope,
    });

    const claims = decodeJwtPayload(exchangeResult.access_token);

    return NextResponse.json({
      accessToken: exchangeResult.access_token,
      tokenType: exchangeResult.token_type ?? "Bearer",
      scope: exchangeResult.scope ?? scope,
      issuedTokenType: exchangeResult.issued_token_type,
      claims: {
        token_use: getClaimString(claims, "token_use"),
        tenant_id: getClaimString(claims, "tenant_id"),
        event_id: getClaimString(claims, "event_id"),
        resource: getClaimString(claims, "resource"),
        scope: getClaimString(claims, "scope"),
        aud: getClaimStringArray(claims, "aud"),
        sub: getClaimString(claims, "sub"),
        exp: claims.exp,
      },
    });
  } catch (error) {
    if (error instanceof ToloIdpSessionError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    if (error instanceof TokenExchangeRequestError) {
      return NextResponse.json(
        {
          error: error.errorCode,
          error_description: error.message,
        },
        { status: error.status },
      );
    }
    throw error;
  }
}
