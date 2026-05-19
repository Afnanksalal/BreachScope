import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans } from "@/lib/schema";
import { eq, desc } from "drizzle-orm";
import { redirect } from "next/navigation";
import { TopBar } from "@/components/dashboard/TopBar";
import { ScansClient } from "./ScansClient";

export default async function ScansPage() {
  const session = await auth();
  const userId = session?.user?.id;
  if (!userId) redirect("/login");

  let allScans: Array<typeof scans.$inferSelect> = [];
  let loadFailed = false;

  try {
    allScans = await db
      .select()
      .from(scans)
      .where(eq(scans.userId, userId))
      .orderBy(desc(scans.createdAt))
      .limit(200);
  } catch (error) {
    loadFailed = true;
    console.error("[dashboard/scans] failed to load scans", error);
  }

  return (
    <>
      <TopBar title="Scans" subtitle={loadFailed ? "Data unavailable" : `${allScans.length} total`} session={session} />
      <div className="flex-1 px-4 py-5 sm:px-6 md:p-8">
        {loadFailed ? (
          <div className="rounded-lg border border-amber-300/20 bg-amber-300/[0.055] p-6">
            <h2 className="text-lg font-semibold text-white">Scan history could not be loaded.</h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-amber-50/65">
              Confirm the production database migration has been applied and that `DATABASE_URL` points to the active application database.
            </p>
          </div>
        ) : (
          <ScansClient scans={allScans} />
        )}
      </div>
    </>
  );
}
