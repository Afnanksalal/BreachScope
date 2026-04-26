import { logger } from "./logger.js";

// ── Firecrawl client (optional — enhanced search when FIRECRAWL_API_KEY is set) ─

let _firecrawl: {
  search: (q: string, opts: object) => Promise<{ success: boolean; data?: Array<{ title?: string; url?: string; markdown?: string }> }>;
  scrapeUrl: (url: string, opts: object) => Promise<{ success: boolean; markdown?: string }>;
} | null = null;

async function tryGetFirecrawl() {
  const apiKey = process.env["FIRECRAWL_API_KEY"];
  if (!apiKey) return null;
  if (_firecrawl) return _firecrawl;
  try {
    const { default: FirecrawlApp } = await import("@mendable/firecrawl-js");
    _firecrawl = new FirecrawlApp({ apiKey }) as unknown as typeof _firecrawl;
    return _firecrawl;
  } catch {
    return null;
  }
}

// ── Core web search — Firecrawl if available, free APIs as fallback ────────────

export async function webSearch(query: string, limit = 10): Promise<string> {
  logger.debug(`[crawl] search: "${query}"`);
  const client = await tryGetFirecrawl();

  if (client) {
    try {
      const result = await client.search(query, { limit, scrapeOptions: { formats: ["markdown"] } });
      if (result.success && result.data?.length) {
        return result.data
          .map((r) => `## ${r.title ?? r.url}\nURL: ${r.url}\n\n${r.markdown ?? ""}`)
          .join("\n\n---\n\n")
          .slice(0, 12_000);
      }
    } catch (e) {
      logger.debug(`[crawl] firecrawl search failed: ${e}`);
    }
  }

  // Fallback: free public vulnerability APIs — no key required
  return freeVulnSearch(query);
}

/** Free threat intelligence using open APIs — OSV.dev, npm advisories, NVD. */
async function freeVulnSearch(query: string): Promise<string> {
  const results: string[] = [];

  // Extract package name from query
  const pkgMatch = query.match(/"([^"]+)"|npm\s+(\S+)|package\s+(\S+)/i);
  const pkg = pkgMatch?.[1] ?? pkgMatch?.[2] ?? pkgMatch?.[3];

  if (pkg) {
    // OSV.dev — comprehensive open vulnerability database
    try {
      const res = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: { name: pkg, ecosystem: "npm" }, version: "" }),
        signal: AbortSignal.timeout(8_000),
      });
      if (res.ok) {
        const data = await res.json() as {
          vulns?: Array<{ id: string; summary?: string; severity?: Array<{ score?: number }>; aliases?: string[] }>;
        };
        if (data.vulns?.length) {
          const entries = data.vulns.slice(0, 10).map((v) => {
            const score = v.severity?.[0]?.score;
            const cves = v.aliases?.filter((a) => a.startsWith("CVE-")).join(", ");
            return `- **${v.id}**${cves ? ` (${cves})` : ""}${score ? ` CVSS ${score}` : ""}: ${v.summary ?? "No summary"}`;
          }).join("\n");
          results.push(`## OSV.dev — ${pkg} (${data.vulns.length} vulnerabilities)\n${entries}`);
        } else {
          results.push(`## OSV.dev — ${pkg}\nNo known vulnerabilities in OSV database.`);
        }
      }
    } catch (e) {
      logger.debug(`[crawl] osv query failed: ${e}`);
    }

    // npm advisory API — free, no auth
    try {
      const res = await fetch("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [pkg]: ["*"] }),
        signal: AbortSignal.timeout(8_000),
      });
      if (res.ok) {
        const data = await res.json() as Record<string, Array<{
          id: number; title: string; severity: string; url: string;
          vulnerable_versions: string; recommendation: string;
        }>>;
        const advisories = data[pkg] ?? [];
        if (advisories.length) {
          const entries = advisories.slice(0, 6).map((a) =>
            `- **[${a.severity.toUpperCase()}]** ${a.title}\n  Affects: \`${a.vulnerable_versions}\` → ${a.recommendation}\n  ${a.url}`
          ).join("\n");
          results.push(`## npm Security Advisories — ${pkg}\n${entries}`);
        }
      }
    } catch (e) {
      logger.debug(`[crawl] npm advisory failed: ${e}`);
    }
  }

  // NVD CVE search for breach/CVE queries
  if (query.toLowerCase().includes("cve") || query.toLowerCase().includes("breach") || query.toLowerCase().includes("vuln")) {
    const keyword = encodeURIComponent(pkg ?? query.slice(0, 60));
    try {
      const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=5`, {
        headers: { "User-Agent": "BreachScope/1.0" },
        signal: AbortSignal.timeout(10_000),
      });
      if (res.ok) {
        const data = await res.json() as {
          vulnerabilities?: Array<{
            cve: {
              id: string;
              descriptions: Array<{ lang: string; value: string }>;
              metrics?: { cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }> };
            };
          }>;
        };
        const cves = data.vulnerabilities ?? [];
        if (cves.length) {
          const entries = cves.slice(0, 5).map((item) => {
            const cve = item.cve;
            const desc = cve.descriptions.find((d) => d.lang === "en")?.value ?? "";
            const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
            return `- **${cve.id}**${score ? ` (${score.baseSeverity} ${score.baseScore})` : ""}: ${desc.slice(0, 200)}`;
          }).join("\n");
          results.push(`## NVD CVE — ${pkg ?? query.slice(0, 40)}\n${entries}`);
        }
      }
    } catch (e) {
      logger.debug(`[crawl] nvd query failed: ${e}`);
    }
  }

  if (results.length > 0) return results.join("\n\n---\n\n");
  return `No threat intelligence found for "${query}". Set FIRECRAWL_API_KEY for full web search capability.`;
}

/** Crawl a single URL and return its content. */
export async function crawlUrl(url: string): Promise<string> {
  logger.debug(`[crawl] scrape: ${url}`);
  const client = await tryGetFirecrawl();

  if (client) {
    try {
      const result = await client.scrapeUrl(url, { formats: ["markdown"] });
      if (result.success && result.markdown) return result.markdown.slice(0, 8_000);
    } catch (e) {
      logger.debug(`[crawl] firecrawl scrape failed: ${e}`);
    }
  }

  // Fallback: plain fetch
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "BreachScope/1.0", "Accept": "text/html,application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    const text = await res.text();
    return text.replace(/<[^>]+>/g, " ").replace(/\s{2,}/g, " ").trim().slice(0, 6_000);
  } catch (e) {
    return `Could not fetch ${url}: ${String(e)}`;
  }
}

/** Security advisories for an npm package. */
export async function fetchNpmAdvisories(packageName: string): Promise<string> {
  return webSearch(`"${packageName}" npm security vulnerability CVE`);
}

/** Fetch the latest security changelog for a known SaaS tool. */
export async function fetchToolChangelog(tool: "supabase" | "vercel" | "github"): Promise<string> {
  const urls: Record<"supabase" | "vercel" | "github", string> = {
    supabase: "https://supabase.com/changelog",
    vercel: "https://vercel.com/changelog",
    github: "https://github.blog/changelog/",
  };
  return crawlUrl(urls[tool]);
}

/** Search GitHub Security Advisories for a package. */
export async function fetchGitHubAdvisory(packageName: string): Promise<string> {
  // OSV covers GitHub advisories, use it first
  const osvResult = await freeVulnSearch(`"${packageName}" vulnerability`);
  if (osvResult && !osvResult.startsWith("No threat")) return osvResult;
  return crawlUrl(`https://github.com/advisories?query=${encodeURIComponent(`ecosystem%3Anpm+${packageName}`)}`);
}

/** Fetch OSV.dev vulnerability data for a package. */
export async function fetchOSVData(packageName: string): Promise<string> {
  return freeVulnSearch(`"${packageName}" vulnerability`);
}
