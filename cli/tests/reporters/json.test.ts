import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { ScanResult, Finding } from "../../src/core/types.js";

vi.mock("fs");

const mockFs = vi.mocked(fs);

beforeEach(() => {
  vi.clearAllMocks();
  mockFs.writeFileSync.mockImplementation(() => undefined);
});

import { renderJsonReport } from "../../src/reporters/json.js";

function makeFindings(overrides: Partial<Finding>[] = []): Finding[] {
  const base: Finding[] = [
    {
      id: "f1",
      title: "Hardcoded secret",
      severity: "critical",
      category: "code",
      description: "API key found in source",
      remediation: "Move to env var",
      file: "src/config.ts",
      line: 12,
      references: [],
    },
    {
      id: "f2",
      title: "Outdated lodash",
      severity: "medium",
      category: "dependency",
      description: "CVE-2021-23337",
      remediation: "Upgrade to lodash@4.17.21",
      tool: "lodash",
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
    },
  ];
  return base.map((f, i) => ({ ...f, ...overrides[i] }));
}

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    target: "/path/to/project",
    startedAt: new Date("2026-04-25T10:00:00.000Z"),
    completedAt: new Date("2026-04-25T10:00:30.000Z"),
    findings: makeFindings(),
    summary: {
      total: 2,
      critical: 1,
      high: 0,
      medium: 1,
      low: 0,
      info: 0,
    },
    metadata: { version: "0.1.0" },
    ...overrides,
  };
}

describe("renderJsonReport", () => {
  it("returns valid JSON string", () => {
    const result = makeScanResult();
    const json = renderJsonReport(result);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("serialized output contains all top-level ScanResult fields", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(renderJsonReport(result));
    expect(parsed).toHaveProperty("target");
    expect(parsed).toHaveProperty("startedAt");
    expect(parsed).toHaveProperty("completedAt");
    expect(parsed).toHaveProperty("summary");
    expect(parsed).toHaveProperty("findings");
    expect(parsed).toHaveProperty("metadata");
  });

  it("preserves finding data faithfully", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(renderJsonReport(result));
    const critical = parsed.findings.find((f: Finding) => f.severity === "critical");
    expect(critical).toBeDefined();
    expect(critical.title).toBe("Hardcoded secret");
    expect(critical.file).toBe("src/config.ts");
    expect(critical.line).toBe(12);
  });

  it("preserves summary counts", () => {
    const result = makeScanResult();
    const parsed = JSON.parse(renderJsonReport(result));
    expect(parsed.summary.total).toBe(2);
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.summary.medium).toBe(1);
  });

  it("writes to file when outputFile is given", () => {
    const result = makeScanResult();
    renderJsonReport(result, "/tmp/report.json");
    expect(mockFs.writeFileSync).toHaveBeenCalledWith(
      "/tmp/report.json",
      expect.stringContaining('"target"'),
      "utf-8",
    );
  });

  it("does not write to file when outputFile is omitted", () => {
    const result = makeScanResult();
    renderJsonReport(result);
    expect(mockFs.writeFileSync).not.toHaveBeenCalled();
  });

  it("returns the same string whether or not file is written", () => {
    const result = makeScanResult();
    const withFile = renderJsonReport(result, "/tmp/r.json");
    vi.clearAllMocks();
    mockFs.writeFileSync.mockImplementation(() => undefined);
    const withoutFile = renderJsonReport(result);
    expect(withFile).toBe(withoutFile);
  });

  it("outputs pretty-printed JSON (indented with 2 spaces)", () => {
    const result = makeScanResult();
    const json = renderJsonReport(result);
    expect(json).toContain("\n  ");
  });

  it("handles empty findings array", () => {
    const result = makeScanResult({ findings: [] });
    const parsed = JSON.parse(renderJsonReport(result));
    expect(parsed.findings).toHaveLength(0);
  });

  it("preserves metadata object", () => {
    const result = makeScanResult({ metadata: { version: "0.1.0", ci: true, branch: "main" } });
    const parsed = JSON.parse(renderJsonReport(result));
    expect(parsed.metadata.version).toBe("0.1.0");
    expect(parsed.metadata.ci).toBe(true);
  });
});
