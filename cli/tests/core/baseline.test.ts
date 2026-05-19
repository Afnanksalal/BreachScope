import { describe, expect, it } from "vitest";
import { createBaseline, filterNewFindings, fingerprintFinding } from "../../src/core/baseline.js";
import type { Finding } from "../../src/core/types.js";

const finding: Finding = {
  id: "xss",
  title: "Reflected XSS",
  severity: "high",
  category: "code",
  description: "Unsanitized input reaches HTML.",
  file: "src/app.ts",
  line: 10,
};

describe("baseline", () => {
  it("creates stable fingerprints", () => {
    expect(fingerprintFinding(finding)).toBe(fingerprintFinding({ ...finding }));
  });

  it("filters findings already present in a baseline", () => {
    const baseline = createBaseline([finding], new Date("2026-01-01T00:00:00Z"));
    const next: Finding = { ...finding, id: "sqli", title: "SQL injection", line: 20 };

    expect(filterNewFindings([finding, next], baseline)).toHaveLength(1);
    expect(filterNewFindings([finding, next], baseline)[0]?.id).toBe("sqli");
  });
});
