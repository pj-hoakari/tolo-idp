"use client";

import { useState } from "react";

const idpUrl = process.env.NEXT_PUBLIC_TOLO_IDP_URL ?? "http://localhost:18080";

export function ChallengeLoginForm({ challenge }: { challenge: string }) {
  const [username, setUsername] = useState("user-123");
  const [password, setPassword] = useState("password");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    const response = await fetch(`${idpUrl}/api/login`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, challenge }),
    }).catch(() => undefined);

    if (response?.ok) {
      const resume = new URL("/oauth2/authorize", idpUrl);
      resume.searchParams.set("challenge", challenge);
      location.assign(resume.href);
      return;
    }
    setError(response?.status === 401
      ? "Invalid username or password (check relation-stub on :18081)"
      : `Login failed; start the sign-in again (${response?.status ?? "network error"})`);
    setSubmitting(false);
  }

  return (
    <main style={{ maxWidth: 480, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>tolo-idp login</h1>
      <form onSubmit={handleSubmit} style={{ display: "grid", gap: "0.75rem" }}>
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
        <button type="submit" disabled={submitting}>Log in</button>
      </form>
      {error && <p role="alert" style={{ color: "crimson" }}>{error}</p>}
    </main>
  );
}
