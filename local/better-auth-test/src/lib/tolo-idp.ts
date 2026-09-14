export const TOLO_IDP_PROVIDER_ID = "tolo-idp";
export const DEFAULT_AUDIENCE = "backend-api";
export const DEFAULT_EVENT_SCOPE = "events.read";
export const RESOURCE_HOST = "api.example.com";

const TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export type ToloIdpConfig = {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
};

export type JwtPayload = Record<string, unknown>;

export type TokenExchangeSuccess = {
  access_token: string;
  token_type?: string;
  scope?: string;
  issued_token_type?: string;
};

export type TokenExchangeError = {
  error: string;
  error_description?: string;
};

export function getToloIdpConfig(): ToloIdpConfig {
  return {
    baseUrl: process.env.TOLO_IDP_URL ?? "http://localhost:8080",
    clientId: process.env.TOLO_IDP_CLIENT_ID ?? "client-123",
    clientSecret: process.env.TOLO_IDP_CLIENT_SECRET ?? "secret",
  };
}

export function buildEventResource(tenantId: string, eventId: string): string {
  return `https://${RESOURCE_HOST}/tenants/${tenantId}/events/${eventId}`;
}

export function decodeJwtPayload(jwt: string): JwtPayload {
  const parts = jwt.split(".");
  if (parts.length < 2) {
    throw new Error("Invalid JWT format");
  }
  const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), "=");
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as JwtPayload;
}

export function getClaimString(payload: JwtPayload, key: string): string | undefined {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
}

export function getClaimStringArray(payload: JwtPayload, key: string): string[] {
  const value = payload[key];
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string");
  }
  return [];
}

export function hasScope(payload: JwtPayload, requiredScope: string): boolean {
  const scope = getClaimString(payload, "scope");
  if (!scope) {
    return false;
  }
  const granted = new Set(scope.split(/\s+/).filter(Boolean));
  return requiredScope.split(/\s+/).every((item) => granted.has(item));
}

export async function exchangeForEventAccess(input: {
  subjectToken: string;
  tenantId: string;
  eventId: string;
  audience: string;
  scope: string;
  config?: ToloIdpConfig;
}): Promise<TokenExchangeSuccess> {
  const config = input.config ?? getToloIdpConfig();
  const body = new URLSearchParams({
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    subject_token: input.subjectToken,
    subject_token_type: ACCESS_TOKEN_TYPE,
    audience: input.audience,
    resource: buildEventResource(input.tenantId, input.eventId),
    scope: input.scope,
  });

  const response = await fetch(`${config.baseUrl}/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const json = (await response.json()) as TokenExchangeSuccess | TokenExchangeError;
  if (!response.ok) {
    const error = json as TokenExchangeError;
    throw new TokenExchangeRequestError(
      response.status,
      error.error ?? "token_exchange_failed",
      error.error_description ?? "Token exchange failed",
    );
  }

  if (!("access_token" in json) || typeof json.access_token !== "string") {
    throw new Error("Token exchange response did not include access_token");
  }

  return json;
}

export class TokenExchangeRequestError extends Error {
  readonly status: number;
  readonly errorCode: string;

  constructor(status: number, errorCode: string, message: string) {
    super(message);
    this.status = status;
    this.errorCode = errorCode;
  }
}
