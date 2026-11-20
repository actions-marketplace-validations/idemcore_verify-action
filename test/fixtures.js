import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

export const FIXTURES = root;

export function loadJson(name) {
  return JSON.parse(readFileSync(join(root, name), "utf8"));
}

export const vectorsR2 = loadJson("vectors_r2.json");
export const tamperedR2 = loadJson("tampered_r2.json");
export const audit = loadJson("audit.json");
export const logText = readFileSync(join(root, "log.txt"), "utf8");
