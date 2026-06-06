import type { MetadataRoute } from "next";
import { APP_URL } from "@/lib/site";

const UPDATED = new Date("2026-05-20");

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: APP_URL,
      lastModified: UPDATED,
      changeFrequency: "weekly",
      priority: 1.0,
    },
    {
      url: `${APP_URL}/docs`,
      lastModified: UPDATED,
      changeFrequency: "weekly",
      priority: 0.95,
    },
    {
      url: `${APP_URL}/roadmap`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.7,
    },
    {
      url: `${APP_URL}/legal`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.65,
    },
    {
      url: `${APP_URL}/terms`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.6,
    },
    {
      url: `${APP_URL}/privacy`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.6,
    },
    {
      url: `${APP_URL}/acceptable-use`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.55,
    },
    {
      url: `${APP_URL}/data-protection`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.55,
    },
    {
      url: `${APP_URL}/security`,
      lastModified: UPDATED,
      changeFrequency: "monthly",
      priority: 0.6,
    },
    {
      url: `${APP_URL}/llms.txt`,
      lastModified: UPDATED,
      changeFrequency: "weekly",
      priority: 0.85,
    },
    {
      url: `${APP_URL}/llms-full.txt`,
      lastModified: UPDATED,
      changeFrequency: "weekly",
      priority: 0.85,
    },
  ];
}
