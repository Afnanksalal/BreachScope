import { and, count, eq, inArray, or } from "drizzle-orm";
import { db } from "./db";
import { organizationMembers, organizations, projects } from "./schema";

export const ORG_ROLES = ["owner", "admin", "security", "auditor", "member"] as const;
export type OrgRole = (typeof ORG_ROLES)[number];

const MANAGE_ROLES = new Set<OrgRole>(["owner", "admin"]);
const PROJECT_ROLES = new Set<OrgRole>(["owner", "admin", "security"]);

export function slugify(value: string): string {
  return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80);
}

export function normalizeRole(value: unknown): OrgRole {
  return ORG_ROLES.includes(value as OrgRole) ? value as OrgRole : "member";
}

export async function getUserOrganizations(userId: string) {
  const rows = await db
    .select({
      id: organizations.id,
      name: organizations.name,
      slug: organizations.slug,
      ssoDomain: organizations.ssoDomain,
      role: organizationMembers.role,
      createdAt: organizations.createdAt,
    })
    .from(organizationMembers)
    .innerJoin(organizations, eq(organizationMembers.organizationId, organizations.id))
    .where(eq(organizationMembers.userId, userId));

  if (rows.length === 0) return [];

  const projectCounts = await db
    .select({ organizationId: projects.organizationId, total: count(projects.id) })
    .from(projects)
    .where(inArray(projects.organizationId, rows.map((row) => row.id)))
    .groupBy(projects.organizationId);

  const counts = new Map(projectCounts.map((row) => [row.organizationId, row.total]));
  return rows.map((row) => ({ ...row, projectCount: counts.get(row.id) ?? 0 }));
}

export async function getProjectForUser(userId: string, projectId: string) {
  const memberships = await db
    .select({ organizationId: organizationMembers.organizationId })
    .from(organizationMembers)
    .where(eq(organizationMembers.userId, userId));
  const orgIds = memberships.map((membership) => membership.organizationId);

  const [project] = await db
    .select()
    .from(projects)
    .where(
      and(
        eq(projects.id, projectId),
        orgIds.length > 0
          ? or(eq(projects.ownerUserId, userId), inArray(projects.organizationId, orgIds))
          : eq(projects.ownerUserId, userId),
      ),
    )
    .limit(1);

  return project;
}

export async function canManageOrganization(userId: string, organizationId: string): Promise<boolean> {
  const [membership] = await db
    .select({ role: organizationMembers.role })
    .from(organizationMembers)
    .where(and(eq(organizationMembers.userId, userId), eq(organizationMembers.organizationId, organizationId)))
    .limit(1);
  return membership ? MANAGE_ROLES.has(normalizeRole(membership.role)) : false;
}

export async function canManageProject(userId: string, projectId: string): Promise<boolean> {
  const [project] = await db
    .select({ ownerUserId: projects.ownerUserId, organizationId: projects.organizationId })
    .from(projects)
    .where(eq(projects.id, projectId))
    .limit(1);

  if (!project) return false;
  if (project.ownerUserId === userId) return true;
  if (!project.organizationId) return false;

  const [membership] = await db
    .select({ role: organizationMembers.role })
    .from(organizationMembers)
    .where(and(eq(organizationMembers.userId, userId), eq(organizationMembers.organizationId, project.organizationId)))
    .limit(1);

  return membership ? PROJECT_ROLES.has(normalizeRole(membership.role)) : false;
}
