"use client";

import { useState } from "react";
import { authClient } from "@/lib/auth-client";

export function IdpLoginForm() {
  const [error, setError] = useState<string | null>(null);
  const [oidcLoading, setOidcLoading] = useState(false);

  async function handleOidcSignIn() {
    setError(null);
    setOidcLoading(true);
    try {
      const response = await authClient.signIn.social({
        provider: "tolo-idp",
        callbackURL: "/dashboard",
      });
      if (response.error) throw new Error(response.error.message ?? "OIDC sign-in failed");
    } catch (signInError) {
      setError(signInError instanceof Error ? signInError.message : "OIDC sign-in failed");
      setOidcLoading(false);
    }
  }

  return (
    <main style={{ maxWidth: 480, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>tolo-idp OIDC test</h1>
      <p>
        Start the OIDC Authorization Code flow through better-auth.
        tolo-idp sends the browser to <code>/login</code> with a login challenge.
      </p>

      <button type="button" onClick={handleOidcSignIn} disabled={oidcLoading}>
        {oidcLoading ? "Redirecting..." : "Sign in with tolo-idp"}
      </button>

      {error && <p style={{ color: "crimson" }}>{error}</p>}
    </main>
  );
}
