export default async function AuthErrorPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { error } = await searchParams;
  return (
    <main style={{ maxWidth: 480, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>Sign-in failed</h1>
      <p>
        Error: <code>{typeof error === "string" ? error : "unknown"}</code>
      </p>
      <p>
        <a href="/">Start the sign-in again</a>
      </p>
    </main>
  );
}
