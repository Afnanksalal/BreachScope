import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans } from "@/lib/schema";
import { eq, and } from "drizzle-orm";
import { notFound, redirect } from "next/navigation";
import { TopBar } from "@/components/dashboard/TopBar";
import { ScanDetail } from "./ScanDetail";

export default async function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const session = await auth();
  const userId = session?.user?.id;
  if (!userId) redirect("/login");

  let scan: typeof scans.$inferSelect | undefined;

  try {
    [scan] = await db
      .select()
      .from(scans)
      .where(and(eq(scans.id, id), eq(scans.userId, userId)))
      .limit(1);
  } catch (error) {
    console.error("[dashboard/scan] failed to load scan detail", error);
    return (
      <>
        <TopBar title="Scan" subtitle="Data unavailable" session={session} back="/dashboard/scans" />
        <div className="flex-1 px-4 py-5 sm:px-6 md:p-8">
          <div className="rounded-lg border border-amber-300/20 bg-amber-300/[0.055] p-6">
            <h2 className="text-lg font-semibold text-white">Scan detail could not be loaded.</h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-amber-50/65">
              Confirm the production database migration has been applied and that `DATABASE_URL` points to the active application database.
            </p>
          </div>
        </div>
      </>
    );
  }

  if (!scan) notFound();

  return (
    <>
      <TopBar
        title={scan.project ?? "Unnamed Project"}
        subtitle={new Date(scan.createdAt).toLocaleDateString("en-US", {
          month: "long", day: "numeric", year: "numeric",
        })}
        session={session}
        back="/dashboard/scans"
      />
      <div className="flex-1 px-4 py-5 sm:px-6 md:p-8">
        <ScanDetail scan={scan} />
      </div>
    </>
  );
}
