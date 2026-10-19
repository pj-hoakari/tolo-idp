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
      setError(err instanceof Error ? err.message : "操作に失敗しました");
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
      setResult({ idpSessionEnded: true, message: "Better Auth のセッションは継続しています。Refresh を試せます。" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "ログアウトに失敗しました");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ display: "grid", gap: "0.75rem", marginTop: "2rem" }}>
      <h2>4. Refresh / 5. Revoke</h2>
      <p>Refresh は Better Auth を通じて更新し、新しい Refresh Token の保存も確認します。</p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
        <button disabled={busy} onClick={() => void operate("refresh")}>4. Refresh Token で更新</button>
        <button disabled={busy} onClick={() => void operate("revoke")}>5. Refresh Token を revoke</button>
        <button disabled={busy} onClick={() => void logoutIdp()}>IdP セッションを終了</button>
      </div>
      <p>revoke 後に再度 Refresh を押すと更新が拒否されます。IdP セッション終了だけでは Refresh Token は失効しません。</p>
      {result && <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto" }}>{JSON.stringify(result, null, 2)}</pre>}
      {error && <p role="alert" style={{ color: "crimson" }}>{error}</p>}
      <button disabled={busy} onClick={async () => {
        const response = await authClient.signOut();
        if (response.error) { setError(response.error.message ?? "サインアウトに失敗しました"); return; }
        window.location.assign("/");
      }}>Better Auth からサインアウトしてログインし直す</button>
    </section>
  );
}
