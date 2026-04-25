import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { Sidebar } from "@/components/dashboard/Sidebar";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();
  if (!session) redirect("/login");

  return (
    <div className="min-h-screen bg-surface-0 flex">
      <Sidebar />
      <main className="flex-1 ml-56 flex flex-col min-h-screen">
        {children}
      </main>
    </div>
  );
}
