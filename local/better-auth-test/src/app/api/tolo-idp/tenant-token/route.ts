import { NextResponse } from "next/server";
import {
  getClaimString,
  getClaimStringArray,
} from "@/lib/tolo-idp";
import {
  getTenantAccessTokenInfo,
  ToloIdpSessionError,
} from "@/lib/tolo-idp-session";

export async function GET() {
  try {
    const tenantToken = await getTenantAccessTokenInfo();
    const { claims } = tenantToken;

    return NextResponse.json({
      accountId: tenantToken.account.id,
      providerId: tenantToken.account.providerId,
      accessToken: tenantToken.accessToken,
      claims: {
        token_use: getClaimString(claims, "token_use"),
        tenant_id: tenantToken.tenantId,
        scope: getClaimString(claims, "scope"),
        aud: getClaimStringArray(claims, "aud"),
        resource: getClaimString(claims, "resource"),
        sub: getClaimString(claims, "sub"),
        exp: claims.exp,
      },
    });
  } catch (error) {
    if (error instanceof ToloIdpSessionError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    throw error;
  }
}
