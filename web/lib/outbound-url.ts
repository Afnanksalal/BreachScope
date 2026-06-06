import dns from "node:dns/promises";
import net from "node:net";

export interface OutboundUrlOptions {
  label?: string;
  requireHttps?: boolean;
  allowPrivateNetwork?: boolean;
}

const LOCAL_HOSTS = new Set(["localhost", "localhost.localdomain"]);

export function normalizeOutboundUrl(raw: string, options: OutboundUrlOptions = {}): string {
  const label = options.label ?? "Outbound URL";
  const value = raw.trim();
  if (!value) throw new Error(`${label} is required`);
  if (value.length > 2048) throw new Error(`${label} is too long`);

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }

  const requireHttps = options.requireHttps ?? true;
  if (requireHttps && url.protocol !== "https:") {
    throw new Error(`${label} must use HTTPS`);
  }
  if (!["https:", "http:"].includes(url.protocol)) {
    throw new Error(`${label} must use HTTP or HTTPS`);
  }
  if (url.username || url.password) {
    throw new Error(`${label} must not include credentials`);
  }
  if (!options.allowPrivateNetwork && isPrivateHost(url.hostname)) {
    throw new Error(`${label} cannot target localhost or private network addresses`);
  }

  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

export async function safeOutboundFetch(
  raw: string,
  init: RequestInit,
  options: OutboundUrlOptions = {},
): Promise<Response> {
  const url = normalizeOutboundUrl(raw, options);
  if (!options.allowPrivateNetwork && shouldEnforceDnsSafety()) {
    await assertPublicDns(new URL(url), options.label ?? "Outbound URL");
  }
  return fetch(url, {
    ...init,
    redirect: "error",
    cache: "no-store",
  });
}

function shouldEnforceDnsSafety(): boolean {
  return process.env.NODE_ENV === "production" || process.env.BREACHSCOPE_ENFORCE_DNS_SAFETY === "true";
}

async function assertPublicDns(url: URL, label: string): Promise<void> {
  if (net.isIP(url.hostname)) return;
  const records = await dns.lookup(url.hostname, { all: true }).catch(() => []);
  if (records.length === 0) throw new Error(`${label} host could not be resolved`);
  if (records.some((record) => isPrivateIp(record.address))) {
    throw new Error(`${label} resolves to a private network address`);
  }
}

function isPrivateHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (LOCAL_HOSTS.has(normalized) || normalized.endsWith(".localhost")) return true;
  return isPrivateIp(normalized);
}

function isPrivateIp(value: string): boolean {
  const ipVersion = net.isIP(value);
  if (ipVersion === 4) return isPrivateIpv4(value);
  if (ipVersion === 6) return isPrivateIpv6(value);
  return false;
}

function isPrivateIpv4(value: string): boolean {
  const parts = value.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b = 0] = parts;
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 0
  );
}

function isPrivateIpv6(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("::ffff:127.") ||
    normalized.startsWith("::ffff:10.") ||
    normalized.startsWith("::ffff:192.168.")
  );
}
