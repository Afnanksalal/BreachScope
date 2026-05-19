import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans } from "@/lib/schema";
import { eq, desc } from "drizzle-orm";
import { TopBar } from "@/components/dashboard/TopBar";
import { ScansClient } from "./ScansClient";

export default async function ScansPage() {
  const session = await auth();
  const userId = session!.user!.id!;

  const allScans = await db
    .select()
    .from(scans)
    .where(eq(scans.userId, userId))
    .orderBy(desc(scans.createdAt))
    .limit(200);

  return (
    <>
      <TopBar title="Scans" subtitle={`${allScans.length} total`} session={session} />
      <div className="flex-1 px-4 py-5 sm:px-6 md:p-8">
        <ScansClient scans={allScans} />
      </div>
    </>
  );
}
