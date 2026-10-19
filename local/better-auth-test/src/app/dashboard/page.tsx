"use client";

import { useState } from "react";
import { TokenLifecyclePanel } from "@/components/token-lifecycle-panel";
import { TokenExchangeForm } from "@/components/token-exchange-form";
import { authClient } from "@/lib/auth-client";

export default function DashboardPage() {
  const session = authClient.useSession();
  const [tokenVersion, setTokenVersion] = useState(0);

  return (
    <main style={{ maxWidth: 720, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>OIDC dashboard</h1>
      <p>better-auth session after OIDC callback.</p>
      <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto" }}>
        {JSON.stringify({ user: session.data?.user, expiresAt: session.data?.session.expiresAt }, null, 2)}
      </pre>
      <TokenExchangeForm key={tokenVersion} />
      <TokenLifecyclePanel onRefresh={() => setTokenVersion((value) => value + 1)} />
      <p>
        <a href="/">Back to login</a>
      </p>
    </main>
  );
}
