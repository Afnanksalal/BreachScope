import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { scans } from "@/lib/schema";
import { eq, and } from "drizzle-orm";
import { notFound } from "next/navigation";
import { TopBar } from "@/components/dashboard/TopBar";
import { ScanDetail } from "./ScanDetail";

export default async function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const session = await auth();
  const userId = session!.user!.id!;

  const [scan] = await db
    .select()
    .from(scans)
    .where(and(eq(scans.id, id), eq(scans.userId, userId)))
    .limit(1);

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
      <div className="flex-1 p-8">
        <ScanDetail scan={scan} />
      </div>
    </>
  );
}
