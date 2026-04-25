import { describe, it, expect } from "vitest";
import { encrypt, decrypt, hashApiKey } from "@/lib/crypto";

describe("encrypt / decrypt", () => {
  it("round-trips plaintext correctly", () => {
    const plain = "sk-openai-super-secret-key";
    expect(decrypt(encrypt(plain))).toBe(plain);
  });

  it("produces different ciphertext on each call (random IV)", () => {
    const plain = "same-input";
    expect(encrypt(plain)).not.toBe(encrypt(plain));
  });

  it("stores ciphertext in iv:tag:data format", () => {
    const parts = encrypt("hello").split(":");
    expect(parts).toHaveLength(3);
    // iv = 16 bytes = 32 hex chars
    expect(parts[0]).toHaveLength(32);
    // tag = 16 bytes = 32 hex chars
    expect(parts[1]).toHaveLength(32);
  });

  it("throws on tampered tag", () => {
    const ct = encrypt("hello");
    const parts = ct.split(":");
    // flip last char of tag
    const badTag = parts[1]!.slice(0, -1) + (parts[1]!.endsWith("a") ? "b" : "a");
    expect(() => decrypt(`${parts[0]}:${badTag}:${parts[2]}`)).toThrow();
  });

  it("throws on malformed ciphertext", () => {
    expect(() => decrypt("notvalidciphertext")).toThrow("Invalid ciphertext format");
  });
});

describe("hashApiKey", () => {
  it("returns a 64-char hex string", () => {
    const h = hashApiKey("bs_live_abc123");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", () => {
    const key = "bs_live_xyz";
    expect(hashApiKey(key)).toBe(hashApiKey(key));
  });

  it("is different for different inputs", () => {
    expect(hashApiKey("bs_live_a")).not.toBe(hashApiKey("bs_live_b"));
  });
});
