import fs from "fs";
import path from "path";
import crypto from "crypto";

export type SbomFormat = "cyclonedx" | "spdx";

export interface BomComponent {
  name: string;
  version?: string;
  ecosystem: string;
  scope?: "required" | "optional" | "excluded";
  purl?: string;
  sourceFile: string;
}

export interface BomDocument {
  generatedAt: string;
  target: string;
  components: BomComponent[];
}

export function discoverBom(cwd: string, generatedAt = new Date()): BomDocument {
  const components = [
    ...readPackageJson(cwd),
    ...readPackageLock(cwd),
    ...readRequirements(cwd),
    ...readPyproject(cwd),
    ...readGoMod(cwd),
    ...readCargoLock(cwd),
    ...readGemfileLock(cwd),
    ...readComposerLock(cwd),
    ...readPom(cwd),
    ...readDotnetPackagesLock(cwd),
    ...readMixLock(cwd),
    ...readPubspecLock(cwd),
  ];

  return {
    generatedAt: generatedAt.toISOString(),
    target: cwd,
    components: dedupeComponents(components),
  };
}

export function renderSbom(
  cwd: string,
  format: SbomFormat = "cyclonedx",
  outputFile?: string
): string {
  const bom = discoverBom(cwd);
  const payload = format === "spdx" ? toSpdx(bom) : toCycloneDx(bom);
  const json = JSON.stringify(payload, null, 2);

  if (outputFile) {
    fs.writeFileSync(outputFile, json + "\n", "utf-8");
  } else {
    console.log(json);
  }
  return json;
}

function toCycloneDx(bom: BomDocument): Record<string, unknown> {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${stableUuid(`${bom.target}:${bom.generatedAt}`)}`,
    version: 1,
    metadata: {
      timestamp: bom.generatedAt,
      tools: {
        components: [{
          type: "application",
          name: "BreachScope",
        }],
      },
      component: {
        type: "application",
        name: path.basename(bom.target),
      },
    },
    components: bom.components.map((component) => ({
      type: "library",
      name: component.name,
      version: component.version,
      scope: component.scope ?? "required",
      purl: component.purl,
      properties: [
        { name: "breachscope:ecosystem", value: component.ecosystem },
        { name: "breachscope:sourceFile", value: component.sourceFile },
      ],
    })),
  };
}

function toSpdx(bom: BomDocument): Record<string, unknown> {
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `${path.basename(bom.target)} BreachScope SBOM`,
    documentNamespace: `https://breachscope.local/sbom/${stableUuid(`${bom.target}:${bom.generatedAt}`)}`,
    creationInfo: {
      created: bom.generatedAt,
      creators: ["Tool: BreachScope"],
    },
    packages: bom.components.map((component) => {
      const id = `SPDXRef-Package-${sanitizeSpdxId(`${component.ecosystem}-${component.name}-${component.version ?? "unknown"}`)}`;
      return {
        name: component.name,
        SPDXID: id,
        versionInfo: component.version ?? "NOASSERTION",
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        externalRefs: component.purl
          ? [{
              referenceCategory: "PACKAGE-MANAGER",
              referenceType: "purl",
              referenceLocator: component.purl,
            }]
          : [],
        supplier: "NOASSERTION",
        licenseConcluded: "NOASSERTION",
        licenseDeclared: "NOASSERTION",
        copyrightText: "NOASSERTION",
        annotations: [{
          annotationDate: bom.generatedAt,
          annotationType: "OTHER",
          annotator: "Tool: BreachScope",
          comment: `Detected from ${component.sourceFile} (${component.ecosystem})`,
        }],
      };
    }),
  };
}

function readPackageJson(cwd: string): BomComponent[] {
  const file = path.join(cwd, "package.json");
  if (!fs.existsSync(file)) return [];
  try {
    const pkg = JSON.parse(fs.readFileSync(file, "utf-8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    };
    return [
      ...depsToComponents(pkg.dependencies, "npm", "package.json", "required"),
      ...depsToComponents(pkg.devDependencies, "npm", "package.json", "excluded"),
      ...depsToComponents(pkg.optionalDependencies, "npm", "package.json", "optional"),
      ...depsToComponents(pkg.peerDependencies, "npm", "package.json", "optional"),
    ];
  } catch {
    return [];
  }
}

function readPackageLock(cwd: string): BomComponent[] {
  const file = path.join(cwd, "package-lock.json");
  if (!fs.existsSync(file)) return [];
  try {
    const lock = JSON.parse(fs.readFileSync(file, "utf-8")) as {
      packages?: Record<string, { name?: string; version?: string; dev?: boolean; optional?: boolean }>;
    };
    return Object.entries(lock.packages ?? {})
      .filter(([location]) => location.startsWith("node_modules/"))
      .map(([location, entry]) => {
        const name = entry.name ?? location.replace(/^node_modules\//, "");
        return makeComponent(name, entry.version, "npm", "package-lock.json", entry.dev ? "excluded" : entry.optional ? "optional" : "required");
      });
  } catch {
    return [];
  }
}

function readRequirements(cwd: string): BomComponent[] {
  return ["requirements.txt", "requirements-dev.txt"]
    .flatMap((fileName) => {
      const file = path.join(cwd, fileName);
      if (!fs.existsSync(file)) return [];
      return fs.readFileSync(file, "utf-8")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#") && !line.startsWith("-"))
        .map((line) => {
          const match = line.match(/^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)?\s*([^;\s]+)?/);
          return match ? makeComponent(match[1]!, match[2], "pypi", fileName) : null;
        })
        .filter((component): component is BomComponent => component !== null);
    });
}

function readPyproject(cwd: string): BomComponent[] {
  const file = path.join(cwd, "pyproject.toml");
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, "utf-8");
  const deps = [...raw.matchAll(/["']([A-Za-z0-9_.-]+)(?:[<>=~!]=?([^"']+))?["']/g)];
  return deps.map((match) => makeComponent(match[1]!, match[2]?.trim(), "pypi", "pyproject.toml"));
}

function readGoMod(cwd: string): BomComponent[] {
  const file = path.join(cwd, "go.mod");
  if (!fs.existsSync(file)) return [];
  const components: BomComponent[] = [];
  for (const raw of fs.readFileSync(file, "utf-8").split(/\r?\n/)) {
    const line = raw.trim();
    const match = line.match(/^([A-Za-z0-9_.\-\/]+)\s+(v[^\s]+)/);
    if (match && !line.startsWith("module ")) {
      components.push(makeComponent(match[1]!, match[2], "golang", "go.mod"));
    }
  }
  return components;
}

function readCargoLock(cwd: string): BomComponent[] {
  const file = path.join(cwd, "Cargo.lock");
  if (!fs.existsSync(file)) return [];
  const components: BomComponent[] = [];
  for (const block of fs.readFileSync(file, "utf-8").split("[[package]]")) {
    const name = block.match(/name\s*=\s*"([^"]+)"/)?.[1];
    const version = block.match(/version\s*=\s*"([^"]+)"/)?.[1];
    if (name) components.push(makeComponent(name, version, "cargo", "Cargo.lock"));
  }
  return components;
}

function readGemfileLock(cwd: string): BomComponent[] {
  const file = path.join(cwd, "Gemfile.lock");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf-8")
    .split(/\r?\n/)
    .map((line) => line.match(/^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)/))
    .filter((match): match is RegExpMatchArray => match !== null)
    .map((match) => makeComponent(match[1]!, match[2], "gem", "Gemfile.lock"));
}

function readComposerLock(cwd: string): BomComponent[] {
  const file = path.join(cwd, "composer.lock");
  if (!fs.existsSync(file)) return [];
  try {
    const lock = JSON.parse(fs.readFileSync(file, "utf-8")) as {
      packages?: Array<{ name: string; version?: string }>;
      "packages-dev"?: Array<{ name: string; version?: string }>;
    };
    return [
      ...(lock.packages ?? []).map((pkg) => makeComponent(pkg.name, pkg.version, "composer", "composer.lock")),
      ...(lock["packages-dev"] ?? []).map((pkg) => makeComponent(pkg.name, pkg.version, "composer", "composer.lock", "excluded")),
    ];
  } catch {
    return [];
  }
}

function readPom(cwd: string): BomComponent[] {
  const file = path.join(cwd, "pom.xml");
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, "utf-8");
  return [...raw.matchAll(/<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?(?:<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/g)]
    .map((match) => makeComponent(`${match[1]}:${match[2]}`, match[3], "maven", "pom.xml"));
}

function readDotnetPackagesLock(cwd: string): BomComponent[] {
  const file = path.join(cwd, "packages.lock.json");
  if (!fs.existsSync(file)) return [];
  try {
    const lock = JSON.parse(fs.readFileSync(file, "utf-8")) as { dependencies?: Record<string, Record<string, { resolved?: string }>> };
    return Object.values(lock.dependencies ?? {}).flatMap((frameworkDeps) =>
      Object.entries(frameworkDeps).map(([name, entry]) => makeComponent(name, entry.resolved, "nuget", "packages.lock.json"))
    );
  } catch {
    return [];
  }
}

function readMixLock(cwd: string): BomComponent[] {
  const file = path.join(cwd, "mix.lock");
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, "utf-8");
  return [...raw.matchAll(/"([^"]+)":\s*\{:[a-z_]+,\s*:[a-z_]+,\s*"([^"]+)"/g)]
    .map((match) => makeComponent(match[1]!, match[2], "hex", "mix.lock"));
}

function readPubspecLock(cwd: string): BomComponent[] {
  const file = path.join(cwd, "pubspec.lock");
  if (!fs.existsSync(file)) return [];
  const components: BomComponent[] = [];
  const raw = fs.readFileSync(file, "utf-8").split(/\r?\n/);
  for (let i = 0; i < raw.length; i++) {
    const name = raw[i]?.match(/^  ([A-Za-z0-9_.-]+):$/)?.[1];
    const version = raw.slice(i, i + 8).join("\n").match(/version:\s*"([^"]+)"/)?.[1];
    if (name) components.push(makeComponent(name, version, "pub", "pubspec.lock"));
  }
  return components;
}

function depsToComponents(
  deps: Record<string, string> | undefined,
  ecosystem: string,
  sourceFile: string,
  scope: BomComponent["scope"] = "required"
): BomComponent[] {
  return Object.entries(deps ?? {}).map(([name, version]) => makeComponent(name, version, ecosystem, sourceFile, scope));
}

function makeComponent(
  name: string,
  version: string | undefined,
  ecosystem: string,
  sourceFile: string,
  scope: BomComponent["scope"] = "required"
): BomComponent {
  return {
    name,
    version,
    ecosystem,
    scope,
    sourceFile,
    purl: toPurl(ecosystem, name, version),
  };
}

function toPurl(ecosystem: string, name: string, version?: string): string {
  const type = ecosystem === "pypi" ? "pypi"
    : ecosystem === "golang" ? "golang"
    : ecosystem === "cargo" ? "cargo"
    : ecosystem === "gem" ? "gem"
    : ecosystem === "composer" ? "composer"
    : ecosystem === "maven" ? "maven"
    : ecosystem === "nuget" ? "nuget"
    : ecosystem === "hex" ? "hex"
    : ecosystem === "pub" ? "pub"
    : "npm";
  const encoded = name.split("/").map(encodeURIComponent).join("/");
  return `pkg:${type}/${encoded}${version ? `@${encodeURIComponent(version)}` : ""}`;
}

function dedupeComponents(components: BomComponent[]): BomComponent[] {
  const byKey = new Map<string, BomComponent>();
  for (const component of components) {
    const key = `${component.ecosystem}:${component.name}:${component.version ?? ""}`;
    if (!byKey.has(key)) byKey.set(key, component);
  }
  return [...byKey.values()].sort((a, b) => `${a.ecosystem}:${a.name}`.localeCompare(`${b.ecosystem}:${b.name}`));
}

function stableUuid(input: string): string {
  const hash = crypto.createHash("sha256").update(input).digest("hex");
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}

function sanitizeSpdxId(value: string): string {
  return value.replace(/[^A-Za-z0-9.-]/g, "-").slice(0, 200);
}
