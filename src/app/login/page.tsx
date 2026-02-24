"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";

const API_BASE = "";

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirect = searchParams.get("redirect") || "/dashboard";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Login failed");
        return;
      }
      if (typeof window !== "undefined") {
        localStorage.setItem("accessToken", data.accessToken);
        localStorage.setItem("refreshToken", data.refreshToken ?? "");
        localStorage.setItem("user", JSON.stringify(data.user));
      }
      router.push(redirect);
      router.refresh();
    } catch (err) {
      setError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4">
      <div className="max-w-xl w-full bg-white rounded-xl border shadow-sm p-6">
        <h1 className="text-2xl font-bold text-slate-900 mb-2">Sign in</h1>
        <p className="text-slate-600 text-sm mb-6">
          Enter your credentials to access the dashboard.
        </p>
        <form onSubmit={handleSubmit} className="gap-4 flex flex-col">
          {error && (
            <div
              className="p-3 rounded-lg text-sm bg-red-50 text-red-700 border border-red-200"
              role="alert"
            >
              {error}
            </div>
          )}
          <div>
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              className="mt-2"
            />
          </div>
          <div>
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              className="mt-2"
            />
          </div>
          <div className="flex gap-4 mt-2">
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-3 rounded-lg font-medium bg-blue-600 text-white hover:bg-blue-700 transition disabled:opacity-50"
            >
              {loading ? "Signing in…" : "Sign in"}
            </button>
            <Link
              href="/"
              className="px-6 py-3 rounded-lg font-medium border text-slate-700 hover:bg-slate-100 transition"
            >
              Cancel
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
