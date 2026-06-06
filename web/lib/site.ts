export const DEFAULT_APP_URL = "https://breachscope.vercel.app";
export const APP_URL = normalizeAppUrl(process.env.NEXT_PUBLIC_APP_URL ?? process.env.AUTH_URL ?? DEFAULT_APP_URL);
export const REPO_URL = "https://github.com/Afnanksalal/BreachScope";

function normalizeAppUrl(value: string): string {
  try {
    const url = new URL(value);
    url.hash = "";
    url.search = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return DEFAULT_APP_URL;
  }
}
