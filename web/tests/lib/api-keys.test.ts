import { describe, it, expect } from "vitest";
import { generateApiKey, verifyApiKey } from "@/lib/api-keys";
import { hashApiKey } from "@/lib/crypto";

describe("generateApiKey", () => {
  it("starts with bs_live_ prefix", () => {
    const { fullKey } = generateApiKey();
    expect(fullKey.startsWith("bs_live_")).toBe(true);
  });

  it("prefix is the first 16 chars of fullKey", () => {
    const { fullKey, prefix } = generateApiKey();
    expect(prefix).toBe(fullKey.slice(0, 16));
  });

  it("hash matches sha-256 of fullKey", () => {
    const { fullKey, hash } = generateApiKey();
    expect(hash).toBe(hashApiKey(fullKey));
  });

  it("generates unique keys on each call", () => {
    const a = generateApiKey();
    const b = generateApiKey();
    expect(a.fullKey).not.toBe(b.fullKey);
    expect(a.hash).not.toBe(b.hash);
  });

  it("fullKey is sufficiently long (> 40 chars)", () => {
    const { fullKey } = generateApiKey();
    expect(fullKey.length).toBeGreaterThan(40);
  });
});

describe("verifyApiKey", () => {
  it("returns true for the correct key", () => {
    const { fullKey, hash } = generateApiKey();
    expect(verifyApiKey(fullKey, hash)).toBe(true);
  });

  it("returns false for a different key", () => {
    const { hash } = generateApiKey();
    const { fullKey: otherKey } = generateApiKey();
    expect(verifyApiKey(otherKey, hash)).toBe(false);
  });

  it("returns false for tampered hash", () => {
    const { fullKey, hash } = generateApiKey();
    const tampered = hash.slice(0, -1) + (hash.endsWith("a") ? "b" : "a");
    expect(verifyApiKey(fullKey, tampered)).toBe(false);
  });
});
