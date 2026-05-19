import { describe, expect, it } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { discoverBom, renderSbom } from "../../src/reporters/sbom.js";

describe("SBOM reporter", () => {
  it("discovers npm and Python components", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "breachscope-sbom-"));
    try {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { next: "16.2.6" } }));
      fs.writeFileSync(path.join(dir, "requirements.txt"), "flask==3.0.0\n");

      const bom = discoverBom(dir, new Date("2026-01-01T00:00:00Z"));

      expect(bom.components.some((component) => component.name === "next" && component.ecosystem === "npm")).toBe(true);
      expect(bom.components.some((component) => component.name === "flask" && component.ecosystem === "pypi")).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("renders CycloneDX and SPDX JSON", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "breachscope-sbom-render-"));
    try {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { react: "19.0.0" } }));

      const cyclonedx = JSON.parse(renderSbom(dir, "cyclonedx", path.join(dir, "bom.json"))) as { bomFormat: string; components: unknown[] };
      const spdx = JSON.parse(renderSbom(dir, "spdx", path.join(dir, "sbom.spdx.json"))) as { spdxVersion: string; packages: unknown[] };

      expect(cyclonedx.bomFormat).toBe("CycloneDX");
      expect(cyclonedx.components).toHaveLength(1);
      expect(spdx.spdxVersion).toBe("SPDX-2.3");
      expect(spdx.packages).toHaveLength(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
