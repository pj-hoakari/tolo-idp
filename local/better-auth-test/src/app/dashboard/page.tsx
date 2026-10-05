"use client";

import { TokenExchangeForm } from "@/components/token-exchange-form";
import { authClient } from "@/lib/auth-client";

export default function DashboardPage() {
  const session = authClient.useSession();

  return (
    <main style={{ maxWidth: 720, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>OIDC dashboard</h1>
      <p>better-auth session after OIDC callback.</p>
      <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto" }}>
        {JSON.stringify(session, null, 2)}
      </pre>
      <TokenExchangeForm />
      <p>
        <a href="/">Back to login</a>
      </p>
    </main>
  );
}
