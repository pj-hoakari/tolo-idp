export default async function LoggedOutPage({ searchParams }: { searchParams: Promise<{ state?: string }> }) {
  const { state } = await searchParams;
  return (
    <main style={{ maxWidth: 720, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>IdP session ended</h1>
      <p>tolo-idp redirected back with state: <code>{state ?? "(none)"}</code></p>
      <p>The Better Auth session and refresh token are still active.</p>
      <p>
        <a href="/dashboard">Back to dashboard</a>
      </p>
    </main>
  );
}
