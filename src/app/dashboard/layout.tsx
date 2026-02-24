import { redirect } from "next/navigation";
import DashboardNav from "./DashboardNav";

async function getToken() {
  // Server layout cannot read localStorage; auth check happens in client nav + client dashboard
  return null;
}

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen flex flex-col">
      <DashboardNav />
      <main className="flex-1 p-6">{children}</main>
    </div>
  );
}
