import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { matchFiles } from "../src/glob.js";

test("matchFiles expands brace globs and skips node_modules", () => {
  const root = mkdtempSync(join(tmpdir(), "idemcore-glob-"));
  mkdirSync(join(root, "receipts"));
  mkdirSync(join(root, "node_modules", "x"), { recursive: true });
  writeFileSync(join(root, "receipts", "a.json"), "{}");
  writeFileSync(join(root, "receipts", "b.ndjson"), "{}\n");
  writeFileSync(join(root, "receipts", "c.log"), "ALL 00\n");
  writeFileSync(join(root, "skip.txt"), "no");
  writeFileSync(join(root, "node_modules", "x", "no.json"), "{}");
  const found = matchFiles(root, "**/*.{json,jsonl,ndjson,log}");
  const rels = found.map((f) => f.rel).sort();
  assert.deepEqual(rels, ["receipts/a.json", "receipts/b.ndjson", "receipts/c.log"]);
});
