import type { MetadataRoute } from "next";

const BASE = "https://breachscoope.vercel.app";
const UPDATED = new Date("2026-05-20");

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: BASE,
      lastModified: UPDATED,
      changeFrequency: "weekly",
      priority: 1.0,
    },
    {
      url: `${BASE}/docs`,
      lastModified: UPDATED,
      changeFrequency: "weekly",
      priority: 0.95,
    },
    {
      url: `${BASE}/roadmap`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.7,
    },
    {
      url: `${BASE}/legal`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.65,
    },
    {
      url: `${BASE}/terms`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.6,
    },
    {
      url: `${BASE}/privacy`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.6,
    },
    {
      url: `${BASE}/acceptable-use`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.55,
    },
    {
      url: `${BASE}/data-protection`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.55,
    },
    {
      url: `${BASE}/security`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.6,
    },
    {
      url: `${BASE}/llms.txt`,
      lastModified: UPDATED,
      changeFrequency: "weekly",
      priority: 0.85,
    },
    {
      url: `${BASE}/llms-full.txt`,
      lastModified: UPDATED,
      changeFrequency: "weekly",
      priority: 0.85,
    },
  ];
}
