"use client";

import { useState } from "react";
import { authClient } from "@/lib/auth-client";

const idpUrl = process.env.NEXT_PUBLIC_TOLO_IDP_URL ?? "http://localhost:8080";

type LoginResponse = {
  username: string;
  tenantId: string;
  resource: string;
  authorities: string[];
};

export function IdpLoginForm() {
  const [username, setUsername] = useState("user-123");
  const [password, setPassword] = useState("password");
  const [tenantId, setTenantId] = useState("tenant-a");
  const [idpSessionReady, setIdpSessionReady] = useState(false);
  const [loginResult, setLoginResult] = useState<LoginResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [oidcLoading, setOidcLoading] = useState(false);

  async function handleIdpLogin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    const response = await fetch(`${idpUrl}/api/login`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, tenantId }),
    });

    if (!response.ok) {
      const message = response.status === 403
        ? "Tenant is not allowed"
        : response.status === 401
          ? "Login failed (check credentials and relation-stub on :8081)"
          : "Login failed";
      setError(`${message} (${response.status})`);
      setIdpSessionReady(false);
      setLoginResult(null);
      return;
    }

    const body = (await response.json()) as LoginResponse;
    setLoginResult(body);
    setIdpSessionReady(true);
  }

  async function handleOidcSignIn() {
    setError(null);
    setOidcLoading(true);
    try {
      await authClient.signIn.social({
        provider: "tolo-idp",
        callbackURL: "/dashboard",
      });
    } catch (signInError) {
      setError(signInError instanceof Error ? signInError.message : "OIDC sign-in failed");
      setOidcLoading(false);
    }
  }

  return (
    <main style={{ maxWidth: 480, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>tolo-idp OIDC test</h1>
      <p>
        Step 1 creates an IdP session via <code>/api/login</code>.
        Step 2 starts the OIDC Authorization Code flow through better-auth.
      </p>

      <form onSubmit={handleIdpLogin} style={{ display: "grid", gap: "0.75rem" }}>
        <label>
          Username
          <input value={username} onChange={(event) => setUsername(event.target.value)} required />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </label>
        <label>
          Tenant ID
          <input value={tenantId} onChange={(event) => setTenantId(event.target.value)} required />
        </label>
        <button type="submit">1. Login to IdP</button>
      </form>

      {loginResult && (
        <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto" }}>
          {JSON.stringify(loginResult, null, 2)}
        </pre>
      )}

      <button
        type="button"
        onClick={handleOidcSignIn}
        disabled={!idpSessionReady || oidcLoading}
        style={{ marginTop: "1rem" }}
      >
        {oidcLoading ? "Redirecting..." : "2. Continue with OIDC"}
      </button>

      {error && <p style={{ color: "crimson" }}>{error}</p>}
    </main>
  );
}
