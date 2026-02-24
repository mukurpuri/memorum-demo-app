"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, usePathname } from "next/navigation";

export default function DashboardNav() {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<{ email?: string; name?: string } | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const raw = localStorage.getItem("user");
    const token = localStorage.getItem("accessToken");
    if (!token) {
      router.replace(`/login?redirect=${encodeURIComponent(pathname || "/dashboard")}`);
      return;
    }
    setUser(raw ? JSON.parse(raw) : null);
    setChecked(true);
  }, [router, pathname]);

  function handleLogout() {
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    localStorage.removeItem("user");
    router.replace("/login");
    router.refresh();
  }

  if (!checked) {
    return (
      <header className="border-b p-4 flex items-center justify-between bg-white">
        <span className="text-slate-500">Loading…</span>
      </header>
    );
  }

  return (
    <header className="border-b p-4 flex items-center justify-between bg-white">
      <nav className="flex items-center gap-6">
        <Link href="/dashboard" className="font-semibold text-slate-900">
          Dashboard
        </Link>
        <Link href="/" className="text-slate-600 hover:text-slate-900">
          Home
        </Link>
      </nav>
      <div className="flex items-center gap-4">
        {user && (
          <span className="text-sm text-slate-600">
            {user.name || user.email}
          </span>
        )}
        <button
          type="button"
          onClick={handleLogout}
          className="text-sm font-medium text-slate-700 hover:text-slate-900"
        >
          Log out
        </button>
      </div>
    </header>
  );
}
