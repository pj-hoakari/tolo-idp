import { betterAuth, type BetterAuthOptions } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import Database from "better-sqlite3";

const toloIdpUrl = process.env.TOLO_IDP_URL ?? "http://localhost:18080";

const authOptions: BetterAuthOptions = {
  database: new Database("sqlite.db"),
  plugins: [
    genericOAuth({
      config: [
        {
          providerId: "tolo-idp",
          clientId: process.env.TOLO_IDP_CLIENT_ID ?? "client-123",
          clientSecret: process.env.TOLO_IDP_CLIENT_SECRET ?? "secret",
          // Pin endpoints so a stale discovery cache cannot redirect to auth.example.com.
          authorizationUrl: `${toloIdpUrl}/oauth2/authorize`,
          tokenUrl: `${toloIdpUrl}/oauth2/token`,
          discoveryUrl: `${toloIdpUrl}/.well-known/openid-configuration`,
          scopes: ["openid", "tenant.read", "events.read"],
          pkce: true,
          tokenEndpointAuth: { method: "client_secret_post" },
          requireIdTokenVerification: true,
          disableProviderLogout: true,
          overrideUserInfo: true,
          authorizationUrlParams: {
            audience: "backend-api",
            resource: "https://api.example.com/tenants/tenant-a",
          },
          mapProfileToUser: (profile) => {
            if (typeof profile.sub !== "string" || !profile.sub) {
              throw new Error("OIDC profile is missing sub");
            }
            return {
              email: `${profile.sub}@tolo-idp.local`,
              emailVerified: false,
              name: profile.sub,
            };
          },
        },
      ],
    }),
  ],
};

export const auth = betterAuth(authOptions);
