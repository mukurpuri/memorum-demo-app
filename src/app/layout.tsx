import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ACME SaaS Platform",
  description: "Enterprise resource management",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
