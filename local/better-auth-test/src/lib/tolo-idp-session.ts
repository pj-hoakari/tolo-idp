import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import {
  decodeJwtPayload,
  getClaimString,
  hasScope,
  TOLO_IDP_PROVIDER_ID,
  type JwtPayload,
} from "@/lib/tolo-idp";

export type ToloIdpLinkedAccount = {
  id: string;
  providerId: string;
  accountId: string;
  scopes: string[];
};

export type TenantAccessTokenInfo = {
  account: ToloIdpLinkedAccount;
  accessToken: string;
  claims: JwtPayload;
  tenantId: string;
};

export class ToloIdpSessionError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function requestHeaders() {
  return await headers();
}

export async function requireBetterAuthSession() {
  const session = await auth.api.getSession({
    headers: await requestHeaders(),
  });
  if (!session) {
    throw new ToloIdpSessionError(401, "Sign in required");
  }
  return session;
}

export async function listToloIdpAccounts(): Promise<ToloIdpLinkedAccount[]> {
  await requireBetterAuthSession();
  const accounts = await auth.api.listUserAccounts({
    headers: await requestHeaders(),
  });
  return accounts
    .filter((account) => account.providerId === TOLO_IDP_PROVIDER_ID)
    .map((account) => ({
      id: account.id,
      providerId: account.providerId,
      accountId: account.accountId,
      scopes: account.scopes ?? [],
    }));
}

export async function resolveToloIdpAccount(): Promise<ToloIdpLinkedAccount> {
  const accounts = await listToloIdpAccounts();
  const account = accounts[0];
  if (!account) {
    throw new ToloIdpSessionError(
      400,
      "No linked tolo-idp account found. Complete OIDC sign-in first.",
    );
  }
  return account;
}

export async function getTenantAccessTokenInfo(): Promise<TenantAccessTokenInfo> {
  const account = await resolveToloIdpAccount();
  const tokenResponse = await auth.api.getAccessToken({
    headers: await requestHeaders(),
    body: {
      accountId: account.id,
    },
  });

  const accessToken = tokenResponse.accessToken;
  if (!accessToken) {
    throw new ToloIdpSessionError(400, "tolo-idp access token not found");
  }

  const claims = decodeJwtPayload(accessToken);
  const tokenUse = getClaimString(claims, "token_use");
  if (tokenUse !== "tenant_access") {
    throw new ToloIdpSessionError(
      400,
      `Expected tenant_access token, got ${tokenUse ?? "unknown"}. Re-run OIDC sign-in.`,
    );
  }

  const tenantId = getClaimString(claims, "tenant_id");
  if (!tenantId) {
    throw new ToloIdpSessionError(400, "tenant_access token is missing tenant_id");
  }

  return {
    account,
    accessToken,
    claims,
    tenantId,
  };
}

export function ensureTenantAccessScopes(claims: JwtPayload, requiredScope: string) {
  if (!hasScope(claims, requiredScope)) {
    throw new ToloIdpSessionError(
      400,
      `tenant_access token is missing required scope: ${requiredScope}. Re-run OIDC sign-in.`,
    );
  }
}
