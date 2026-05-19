import { createCipheriv, createDecipheriv, randomBytes, createHash } from "crypto";

const ALGORITHM = "aes-256-gcm";

function getDerivedKey(): Buffer {
  const secret = process.env["ENCRYPTION_KEY"];
  if (!secret) throw new Error("ENCRYPTION_KEY env var is not set");
  return createHash("sha256").update(secret).digest();
}

export function encrypt(plaintext: string): string {
  const key = getDerivedKey();
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Format: iv(hex):tag(hex):encrypted(hex)
  return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

export function decrypt(ciphertext: string): string {
  const key = getDerivedKey();
  const [ivHex, tagHex, encHex] = ciphertext.split(":");

  if (!ivHex || !tagHex || !encHex) throw new Error("Invalid ciphertext format");

  const iv = Buffer.from(ivHex, "hex");
  const tag = Buffer.from(tagHex, "hex");
  const encrypted = Buffer.from(encHex, "hex");

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  return decipher.update(encrypted).toString("utf8") + decipher.final("utf8");
}

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}
