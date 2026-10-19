"use client";

import { useState } from "react";
import { authClient } from "@/lib/auth-client";

export function TokenLifecyclePanel({ onRefresh }: { onRefresh: () => void }) {
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function operate(action: "refresh" | "revoke") {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const response = await fetch("/api/tolo-idp/tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(`${body.error_description ?? body.error} (${response.status})`);
      setResult(body);
      if (action === "refresh") onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Token operation failed");
    } finally {
      setBusy(false);
    }
  }

  async function logoutIdp() {
    setBusy(true);
    setError(null);
    try {
      const baseUrl = process.env.NEXT_PUBLIC_TOLO_IDP_URL ?? "http://localhost:18080";
      const response = await fetch(`${baseUrl}/api/logout`, { method: "POST", credentials: "include" });
      if (!response.ok) throw new Error(`IdP logout failed (${response.status})`);
      setResult({ idpSessionEnded: true, message: "The Better Auth session is still active. You can try refreshing the token." });
    } catch (err) {
      setError(err instanceof Error ? err.message : "IdP logout failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ display: "grid", gap: "1rem", marginTop: "2rem" }}>
      <h2>4. Refresh / 5. Revoke</h2>
      <p>Refresh the token through Better Auth and check that the rotated refresh token is saved.</p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
        <button disabled={busy} onClick={() => void operate("refresh")}>4. Refresh tokens</button>
        <button disabled={busy} onClick={() => void operate("revoke")}>5. Revoke refresh token</button>
        <button disabled={busy} onClick={() => void logoutIdp()}>End IdP session</button>
      </div>
      <p>After revocation, refreshing again should fail. Ending the IdP session alone does not revoke the refresh token.</p>
      {result && <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto" }}>{JSON.stringify(result, null, 2)}</pre>}
      {error && <p role="alert" style={{ color: "crimson" }}>{error}</p>}
      <button disabled={busy} onClick={async () => {
        const response = await authClient.signOut();
        if (response.error) { setError(response.error.message ?? "Sign-out failed"); return; }
        window.location.assign("/");
      }}>Sign out of Better Auth and sign in again</button>
    </section>
  );
}
