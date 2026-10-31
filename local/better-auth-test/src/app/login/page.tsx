import { redirect } from "next/navigation";
import { ChallengeLoginForm } from "@/components/challenge-login-form";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const challenge = (await searchParams).challenge;
  if (typeof challenge !== "string" || !challenge) {
    redirect("/auth/error?error=no_challenge");
  }
  return <ChallengeLoginForm challenge={challenge} />;
}
