import Link from "next/link";

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4">
      <div className="text-center max-w-xl">
        <h1 className="text-4xl font-bold text-slate-900 mb-3">
          ACME SaaS Platform
        </h1>
        <p className="text-slate-600 mb-8">
          Enterprise resource management with secure authentication, teams, and
          subscriptions.
        </p>
        <div className="flex gap-4 justify-center flex-wrap">
          <Link
            href="/login"
            className="px-6 py-3 rounded-lg font-medium bg-blue-600 text-white hover:bg-blue-700 transition"
          >
            Sign in
          </Link>
          <Link
            href="/dashboard"
            className="px-6 py-3 rounded-lg font-medium border text-slate-700 hover:bg-slate-100 transition"
          >
            Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
