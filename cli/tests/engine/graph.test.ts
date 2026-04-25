import { describe, it, expect } from "vitest";
import { DepGraph, shouldSkipPackage } from "../../src/engine/graph.js";

describe("DepGraph", () => {
  describe("addNode / hasNode", () => {
    it("reports false for a node that has not been added", () => {
      const g = new DepGraph();
      expect(g.hasNode("express")).toBe(false);
    });

    it("reports true after adding a node", () => {
      const g = new DepGraph();
      g.addNode("express", "dependency", 45, 0);
      expect(g.hasNode("express")).toBe(true);
    });

    it("does not overwrite an existing node", () => {
      const g = new DepGraph();
      g.addNode("express", "dependency", 45, 0);
      g.addNode("express", "tool", 99, 1); // should be ignored
      const json = g.toJSON();
      const node = json.nodes.find((n) => n.id === "express");
      expect(node?.riskScore).toBe(45);
    });
  });

  describe("addEdge / toJSON edges", () => {
    it("records an edge between two nodes", () => {
      const g = new DepGraph();
      g.addNode("next", "tool", 30, 0);
      g.addNode("react", "dependency", 20, 1);
      g.addEdge("next", "react");

      const json = g.toJSON();
      expect(json.edges).toHaveLength(1);
      expect(json.edges[0]).toEqual({ from: "next", to: "react" });
    });

    it("deduplicates duplicate edges", () => {
      const g = new DepGraph();
      g.addEdge("a", "b");
      g.addEdge("a", "b");
      const json = g.toJSON();
      expect(json.edges).toHaveLength(1);
    });

    it("stores multiple distinct edges", () => {
      const g = new DepGraph();
      g.addEdge("a", "b");
      g.addEdge("a", "c");
      g.addEdge("b", "c");
      const json = g.toJSON();
      expect(json.edges).toHaveLength(3);
    });
  });

  describe("toJSON nodes", () => {
    it("serialises node data correctly", () => {
      const g = new DepGraph();
      g.addNode("openai", "tool", 72, 0);
      const json = g.toJSON();
      expect(json.nodes).toHaveLength(1);
      expect(json.nodes[0]).toEqual({ id: "openai", kind: "tool", riskScore: 72, depth: 0 });
    });

    it("returns empty nodes and edges for empty graph", () => {
      const g = new DepGraph();
      const json = g.toJSON();
      expect(json.nodes).toHaveLength(0);
      expect(json.edges).toHaveLength(0);
    });

    it("handles multiple nodes", () => {
      const g = new DepGraph();
      g.addNode("axios", "dependency", 35, 0);
      g.addNode("stripe", "tool", 60, 1);
      const json = g.toJSON();
      expect(json.nodes).toHaveLength(2);
    });
  });
});

describe("shouldSkipPackage", () => {
  it("skips known noisy dev tools", () => {
    for (const pkg of ["typescript", "eslint", "prettier", "vitest", "webpack", "vite"]) {
      expect(shouldSkipPackage(pkg)).toBe(true);
    }
  });

  it("skips all @types/* packages", () => {
    expect(shouldSkipPackage("@types/node")).toBe(true);
    expect(shouldSkipPackage("@types/react")).toBe(true);
    expect(shouldSkipPackage("@types/express")).toBe(true);
  });

  it("skips test framework patterns", () => {
    expect(shouldSkipPackage("jest")).toBe(true);
    expect(shouldSkipPackage("mocha")).toBe(true);
    expect(shouldSkipPackage("cypress")).toBe(true);
    expect(shouldSkipPackage("playwright")).toBe(true);
  });

  it("does not skip security-relevant packages", () => {
    expect(shouldSkipPackage("openai")).toBe(false);
    expect(shouldSkipPackage("stripe")).toBe(false);
    expect(shouldSkipPackage("axios")).toBe(false);
    expect(shouldSkipPackage("express")).toBe(false);
    expect(shouldSkipPackage("@prisma/client")).toBe(false);
  });

  it("does not skip scoped non-types packages", () => {
    expect(shouldSkipPackage("@aws-sdk/client-s3")).toBe(false);
    expect(shouldSkipPackage("@supabase/supabase-js")).toBe(false);
  });

  it("skips utility packages with no security surface", () => {
    expect(shouldSkipPackage("lodash")).toBe(true);
    expect(shouldSkipPackage("clsx")).toBe(true);
    expect(shouldSkipPackage("date-fns")).toBe(true);
  });
});
