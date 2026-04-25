import type { MetadataRoute } from "next";

const BASE    = "https://breachscoope.vercel.app";
const UPDATED = new Date("2026-04-25");

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url:             BASE,
      lastModified:    UPDATED,
      changeFrequency: "weekly",
      priority:        1.0,
    },
    {
      url:             `${BASE}/docs`,
      lastModified:    UPDATED,
      changeFrequency: "weekly",
      priority:        0.9,
    },
    {
      url:             `${BASE}/llms.txt`,
      lastModified:    UPDATED,
      changeFrequency: "weekly",
      priority:        0.8,
    },
    {
      url:             `${BASE}/llms-full.txt`,
      lastModified:    UPDATED,
      changeFrequency: "weekly",
      priority:        0.8,
    },
    {
      url:             `${BASE}/login`,
      lastModified:    UPDATED,
      changeFrequency: "yearly",
      priority:        0.3,
    },
  ];
}
