import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { vectorsR2, tamperedR2, audit, logText } from "./fixtures.js";
import { run } from "../src/main.js";

function workspace(files) {
  const root = mkdtempSync(join(tmpdir(), "idemcore-action-"));
  for (const [rel, body] of Object.entries(files)) {
    const full = join(root, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, typeof body === "string" ? body : JSON.stringify(body, null, 2));
  }
  return root;
}

test("r2 receipt passes with its own public key; tampered receipt fails the job", async () => {
  const root = workspace({
    "keys.json": vectorsR2.public_jwk,
    "receipts/good.json": { receipt: vectorsR2.receipt, log_text: logText },
    "receipts/bad.json": tamperedR2,
  });
  const out = join(root, "out.txt");
  const summary = join(root, "summary.md");
  const res = await run({
    GITHUB_WORKSPACE: root,
    GITHUB_OUTPUT: out,
    GITHUB_STEP_SUMMARY: summary,
    INPUT_PATH: "receipts/*.json",
    INPUT_KEYS: "keys.json",
    INPUT_FAIL_ON_ERROR: "true",
  }, root);
  assert.equal(res.checked, 2);
  assert.equal(res.passed, 1);
  assert.equal(res.failed, 1);
  assert.equal(res.exitCode, 1);
  const output = readFileSync(out, "utf8");
  assert.match(output, /passed=1/);
  assert.match(output, /failed=1/);
  assert.match(output, /checked=2/);
  const md = readFileSync(summary, "utf8");
  assert.match(md, /\| result \|/);
  assert.match(md, /pass/);
  assert.match(md, /FAIL/);
});

test("audit export (events and signed daily root) from the public vectors passes", async () => {
  const root = workspace({
    "keys.json": { keys: audit.keys },
    "exports/audit.json": audit.audit,
  });
  const res = await run({
    GITHUB_WORKSPACE: root,
    INPUT_PATH: "exports/*.json",
    INPUT_KEYS: "keys.json",
  }, root);
  assert.equal(res.failed, 0);
  assert.ok(res.passed >= 1);
  assert.equal(res.exitCode, 0);
  assert.ok(res.rows.some((r) => r.kind === "audit" && r.ok));
});

test("no matches with require_files fails", async () => {
  const root = workspace({ "readme.txt": "nothing here" });
  const res = await run({
    GITHUB_WORKSPACE: root,
    INPUT_PATH: "receipts/**/*.json",
    INPUT_REQUIRE_FILES: "true",
  }, root);
  assert.equal(res.checked, 0);
  assert.equal(res.exitCode, 1);
});

test("public share URL file is fetched and checked (mocked)", async () => {
  const shareId = "rshare_" + "ab".repeat(16);
  const root = workspace({
    "keys.json": vectorsR2.public_jwk,
    "shares/link.json": { share_url: `https://api.idemcore.net/v1/public/receipts/${shareId}` },
  });
  let fetched = "";
  const res = await run({
    GITHUB_WORKSPACE: root,
    INPUT_PATH: "shares/*.json",
    INPUT_KEYS: "keys.json",
  }, root, {
    fetchImpl: async (url) => {
      fetched = url;
      return {
        ok: true,
        status: 200,
        json: async () => ({ public: true, receipt: vectorsR2.receipt, log_text: logText }),
      };
    },
  });
  assert.equal(fetched, `https://api.idemcore.net/v1/public/receipts/${shareId}`);
  assert.equal(res.failed, 0);
  assert.equal(res.exitCode, 0);
  assert.ok(res.rows.some((r) => r.ok && r.id === vectorsR2.receipt.receipt_id));
});

test("public share 404 fails the job and does not ask for an API key", async () => {
  const shareId = "rshare_" + "cd".repeat(16);
  const root = workspace({
    "shares/link.txt": `https://idemcore.net/r/${shareId}\n`,
  });
  const res = await run({
    GITHUB_WORKSPACE: root,
    INPUT_PATH: "shares/*",
  }, root, {
    fetchImpl: async () => ({ ok: false, status: 404, json: async () => ({}) }),
  });
  assert.equal(res.failed, 1);
  assert.equal(res.exitCode, 1);
  assert.match(res.rows[0].errors.join(" "), /HTTP 404/);
});
