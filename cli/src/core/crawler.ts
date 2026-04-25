import FirecrawlApp from "@mendable/firecrawl-js";
import { logger } from "./logger.js";

let _client: FirecrawlApp | null = null;

export function getFirecrawl(): FirecrawlApp {
  if (!_client) {
    const apiKey = process.env["FIRECRAWL_API_KEY"];
    if (!apiKey) {
      throw new Error(
        "FIRECRAWL_API_KEY is not set. Export it or add it to breachscope.yaml under ai.firecrawlApiKey."
      );
    }
    _client = new FirecrawlApp({ apiKey });
  }
  return _client;
}

/** Search the web and return concatenated markdown of top results. */
export async function webSearch(query: string, limit = 5): Promise<string> {
  logger.debug(`[crawl] search: "${query}"`);
  const client = getFirecrawl();

  try {
    const result = await client.search(query, { limit, scrapeOptions: { formats: ["markdown"] } });
    if (!result.success || !result.data?.length) return "No results found.";

    return result.data
      .map((r) => `## ${r.title ?? r.url}\nURL: ${r.url}\n\n${r.markdown ?? ""}`)
      .join("\n\n---\n\n")
      .slice(0, 12000); // keep tokens reasonable
  } catch (e) {
    logger.debug(`[crawl] search failed: ${e}`);
    return `Search failed: ${String(e)}`;
  }
}

/** Crawl a single URL and return its markdown content. */
export async function crawlUrl(url: string): Promise<string> {
  logger.debug(`[crawl] scrape: ${url}`);
  const client = getFirecrawl();

  try {
    const result = await client.scrapeUrl(url, { formats: ["markdown"] });
    if (!result.success) return `Could not scrape ${url}`;
    return (result.markdown ?? "").slice(0, 8000);
  } catch (e) {
    logger.debug(`[crawl] scrape failed: ${e}`);
    return `Scrape failed: ${String(e)}`;
  }
}

/** Look up a specific npm package's security advisories. */
export async function fetchNpmAdvisories(packageName: string): Promise<string> {
  return webSearch(`site:github.com/advisories "${packageName}" npm security vulnerability`);
}

/** Fetch the latest security changelog / release notes for a tool. */
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
  return crawlUrl(
    `https://github.com/advisories?query=${encodeURIComponent(`ecosystem%3Anpm+${packageName}`)}`
  );
}

/** Fetch OSV.dev vulnerability data for a package. */
export async function fetchOSVData(packageName: string): Promise<string> {
  return crawlUrl(
    `https://osv.dev/list?q=${encodeURIComponent(packageName)}&ecosystem=npm`
  );
}
