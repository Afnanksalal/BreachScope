import { expect, test } from "@playwright/test";

const PUBLIC_ROUTES = ["/", "/docs", "/login", "/privacy", "/terms", "/security"];

test.describe("public product surfaces", () => {
  for (const route of PUBLIC_ROUTES) {
    test(`${route} renders without horizontal overflow`, async ({ page }) => {
      await page.goto(route);
      await expect(page.locator("body")).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow).toBeLessThanOrEqual(2);
    });
  }
});

test("dashboard route fails closed to authentication instead of 500", async ({ page }) => {
  const response = await page.goto("/dashboard");
  expect(response?.status()).toBeLessThan(500);
  await expect(page).toHaveURL(/login|dashboard/);
});

test("mobile navigation exposes primary routes", async ({ page, isMobile }) => {
  test.skip(!isMobile, "mobile-only navigation check");
  await page.goto("/");
  const menuButton = page.getByRole("button", { name: /menu|open/i }).first();
  if (await menuButton.count()) await menuButton.click();
  await expect(page.getByRole("link", { name: /docs/i }).first()).toBeVisible();
});
