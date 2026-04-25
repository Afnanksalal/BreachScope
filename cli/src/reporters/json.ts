import fs from "fs";
import type { ScanResult } from "../core/types.js";

export function renderJsonReport(result: ScanResult, outputFile?: string): string {
  const json = JSON.stringify(result, null, 2);
  if (outputFile) {
    fs.writeFileSync(outputFile, json, "utf-8");
  } else {
    console.log(json);
  }
  return json;
}
