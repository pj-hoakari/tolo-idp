import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import Database from "better-sqlite3";

const toloIdpUrl = process.env.TOLO_IDP_URL ?? "http://localhost:8080";

export const auth = betterAuth({
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
          authentication: "post",
          mapProfileToUser: (profile) => ({
            email: `${String(profile.id)}@tolo-idp.local`,
            emailVerified: true,
            name: String(profile.id),
          }),
        },
      ],
    }),
  ],
});
