import { describe, expect, it } from "vitest";
import { normalizeOutboundUrl } from "@/lib/outbound-url";

describe("normalizeOutboundUrl", () => {
  it("requires HTTPS for outbound provider URLs", () => {
    expect(() => normalizeOutboundUrl("http://example.com/hook", { label: "Webhook" }))
      .toThrow("Webhook must use HTTPS");
  });

  it("blocks localhost and private network targets", () => {
    expect(() => normalizeOutboundUrl("https://localhost/hook", { label: "Webhook" }))
      .toThrow("private network");
    expect(() => normalizeOutboundUrl("https://127.0.0.1/hook", { label: "Webhook" }))
      .toThrow("private network");
    expect(() => normalizeOutboundUrl("https://10.0.0.10/hook", { label: "Webhook" }))
      .toThrow("private network");
  });

  it("normalizes safe public URLs", () => {
    expect(normalizeOutboundUrl("https://example.com/hook#secret", { label: "Webhook" }))
      .toBe("https://example.com/hook");
  });
});
