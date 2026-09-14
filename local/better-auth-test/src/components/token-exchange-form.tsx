"use client";

import { useCallback, useEffect, useState } from "react";

type TenantTokenPreview = {
  accessToken: string;
  claims: {
    token_use?: string;
    tenant_id?: string;
    scope?: string;
    aud?: string[];
    resource?: string;
    sub?: string;
    exp?: number;
  };
};

type TokenExchangeResult = {
  accessToken: string;
  tokenType: string;
  scope: string;
  claims: {
    token_use?: string;
    tenant_id?: string;
    event_id?: string;
    resource?: string;
    scope?: string;
    aud?: string[];
    sub?: string;
    exp?: number;
  };
};

type ApiError = {
  error?: string;
  error_description?: string;
};

function readApiError(body: ApiError, fallback: string): string {
  return body.error_description ?? body.error ?? fallback;
}

export function TokenExchangeForm() {
  const [eventId, setEventId] = useState("event-1");
  const [scope, setScope] = useState("events.read");
  const [audience, setAudience] = useState("backend-api");
  const [tenantToken, setTenantToken] = useState<TenantTokenPreview | null>(null);
  const [exchangeResult, setExchangeResult] = useState<TokenExchangeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [loadingExchange, setLoadingExchange] = useState(false);

  const loadTenantToken = useCallback(async () => {
    setLoadingPreview(true);
    setError(null);
    try {
      const response = await fetch("/api/tolo-idp/tenant-token");
      const body = (await response.json()) as TenantTokenPreview | ApiError;
      if (!response.ok) {
        throw new Error(readApiError(body as ApiError, "Failed to load tenant token"));
      }
      setTenantToken(body as TenantTokenPreview);
    } catch (previewError) {
      setTenantToken(null);
      setError(previewError instanceof Error ? previewError.message : "Failed to load tenant token");
    } finally {
      setLoadingPreview(false);
    }
  }, []);

  useEffect(() => {
    void loadTenantToken();
  }, [loadTenantToken]);

  async function handleExchange(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoadingExchange(true);
    setError(null);
    setExchangeResult(null);

    try {
      const response = await fetch("/api/token-exchange", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          eventId,
          scope,
          audience,
        }),
      });
      const body = (await response.json()) as TokenExchangeResult | ApiError;
      if (!response.ok) {
        throw new Error(readApiError(body as ApiError, "Token exchange failed"));
      }
      setExchangeResult(body as TokenExchangeResult);
    } catch (exchangeError) {
      setError(exchangeError instanceof Error ? exchangeError.message : "Token exchange failed");
    } finally {
      setLoadingExchange(false);
    }
  }

  return (
    <section style={{ display: "grid", gap: "1rem", marginTop: "2rem" }}>
      <h2>3. Token Exchange</h2>
      <p>
        Exchange the stored <code>tenant_access</code> token for an <code>event_access</code> token.
        If scopes were recently expanded, re-run OIDC sign-in on the home page first.
      </p>

      <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
        <button type="button" onClick={() => void loadTenantToken()} disabled={loadingPreview}>
          {loadingPreview ? "Refreshing..." : "Refresh tenant_access preview"}
        </button>
      </div>

      {tenantToken && (
        <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto" }}>
          {JSON.stringify(tenantToken.claims, null, 2)}
        </pre>
      )}

      <form onSubmit={handleExchange} style={{ display: "grid", gap: "0.75rem" }}>
        <label>
          Event ID
          <input value={eventId} onChange={(event) => setEventId(event.target.value)} required />
        </label>
        <label>
          Scope
          <input value={scope} onChange={(event) => setScope(event.target.value)} required />
        </label>
        <label>
          Audience
          <input value={audience} onChange={(event) => setAudience(event.target.value)} required />
        </label>
        <button type="submit" disabled={loadingExchange}>
          {loadingExchange ? "Exchanging..." : "3. Exchange for event_access"}
        </button>
      </form>

      {exchangeResult && (
        <>
          <h3>event_access claims</h3>
          <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto" }}>
            {JSON.stringify(exchangeResult.claims, null, 2)}
          </pre>
          <details>
            <summary>Raw access token</summary>
            <pre style={{ background: "#f4f4f4", padding: "1rem", overflow: "auto", whiteSpace: "pre-wrap" }}>
              {exchangeResult.accessToken}
            </pre>
          </details>
        </>
      )}

      {error && <p style={{ color: "crimson" }}>{error}</p>}
    </section>
  );
}
