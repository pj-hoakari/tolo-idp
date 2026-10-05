import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "tolo-idp better-auth test",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ja">
      <body>{children}</body>
    </html>
  );
}
