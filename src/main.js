#!/usr/bin/env node
/**
 * GitHub Action / local CLI entry: scan a workspace and check receipts,
 * token logs, and audit exports offline. No API key, no model.
 */
import { readFileSync, existsSync, appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { extractPublicShareLinks, inspectDocument, inspectText, loadTrustedKeys } from "@idemcore/verify-lib";
import { matchFiles } from "./glob.js";

function boolInput(v, fallback = true) {
  if (v === undefined || v === null || v === "") return fallback;
  const s = String(v).trim().toLowerCase();
  if (["false", "0", "no", "off"].includes(s)) return false;
  if (["true", "1", "yes", "on"].includes(s)) return true;
  return fallback;
}

function writeOutput(env, name, value) {
  const file = env.GITHUB_OUTPUT;
  if (file) appendFileSync(file, `${name}=${value}\n`);
}

function writeSummary(env, md) {
  const file = env.GITHUB_STEP_SUMMARY;
  const text = md.endsWith("\n") ? md : md + "\n";
  if (file) appendFileSync(file, text);
}

function loadKeysFile(workspace, rel) {
  if (!rel) return null;
  const path = resolve(workspace, rel);
  if (!existsSync(path)) throw new Error(`keys file not found: ${rel}`);
  return JSON.parse(readFileSync(path, "utf8"));
}

async function inspectPublicShares(text, keys, fetchImpl) {
  const links = extractPublicShareLinks(text);
  if (!links.length) return [];
  const fetchFn = fetchImpl || globalThis.fetch;
  if (typeof fetchFn !== "function") {
    return links.map((link) => ({
      kind: "public-share",
      id: link.shareId,
      ok: false,
      details: { errors: ["fetch is not available to resolve public share links"] },
    }));
  }
  const items = [];
  for (const link of links) {
    try {
      const res = await fetchFn(link.url, { headers: { Accept: "application/json" } });
      if (!res.ok) {
        items.push({
          kind: "public-share",
          id: link.shareId,
          ok: false,
          details: { errors: [`public share ${link.url} returned HTTP ${res.status}`] },
        });
        continue;
      }
      const data = await res.json();
      const found = await inspectDocument(data, { keys });
      if (!found.length) {
        items.push({
          kind: "public-share",
          id: link.shareId,
          ok: false,
          details: { errors: ["the public share response did not contain a signed receipt"] },
        });
      } else {
        items.push(...found);
      }
    } catch (e) {
      items.push({
        kind: "public-share",
        id: link.shareId,
        ok: false,
        details: { errors: [e.message] },
      });
    }
  }
  return items;
}

export async function run(env = process.env, cwd = process.cwd(), opts = {}) {
  const workspace = env.GITHUB_WORKSPACE || cwd;
  const glob = env.INPUT_PATH || "**/*.{json,jsonl,ndjson,log}";
  const failOnError = boolInput(env.INPUT_FAIL_ON_ERROR, true);
  const requireFiles = boolInput(env.INPUT_REQUIRE_FILES, true);
  const keySpec = loadKeysFile(workspace, env.INPUT_KEYS || "");
  const keys = await loadTrustedKeys(keySpec, { source: env.INPUT_KEYS ? "keys-file" : "bundled" });
  const fetchImpl = opts.fetchImpl;

  const matched = matchFiles(workspace, glob);
  const rows = [];
  for (const file of matched) {
    const text = readFileSync(file.full, "utf8");
    // Skip obviously non-artifact docs accidentally caught by a broad glob.
    if (file.rel.endsWith("SOURCE.md") || file.rel.endsWith("package-lock.json")) continue;
    let items = await inspectText(text, { keys });
    // A JSON file that is not a receipt/log/audit yields a single "unknown" item;
    // ignore those so a broad default glob does not fail the whole repo.
    let useful = items.filter((it) => it.kind !== "unknown");
    if (!useful.length) useful = await inspectPublicShares(text, keys, fetchImpl);
    if (!useful.length) continue;
    for (const it of useful) {
      rows.push({
        file: file.rel,
        kind: it.kind,
        id: it.id,
        ok: it.ok,
        errors: it.details?.errors || [],
      });
    }
  }

  const passed = rows.filter((r) => r.ok).length;
  const failed = rows.filter((r) => !r.ok).length;
  const checked = rows.length;

  const tableLines = [
    "## Idemcore offline checks",
    "",
    `| file | kind | id | result | notes |`,
    `| --- | --- | --- | --- | --- |`,
    ...rows.map((r) => {
      const notes = r.ok ? "" : r.errors.join("; ").replace(/\|/g, "\\|");
      return `| ${r.file} | ${r.kind} | ${r.id} | ${r.ok ? "pass" : "FAIL"} | ${notes} |`;
    }),
    "",
    `Checked **${checked}** · passed **${passed}** · failed **${failed}**.`,
    "",
    "These checks run offline. No API key is used.",
    "",
  ];
  const summary = tableLines.join("\n");
  writeSummary(env, summary);
  writeOutput(env, "passed", String(passed));
  writeOutput(env, "failed", String(failed));
  writeOutput(env, "checked", String(checked));

  const result = { passed, failed, checked, rows, summary };
  if (requireFiles && checked === 0) {
    result.error = `no receipts, token logs, or audit exports matched ${glob}`;
    return { ...result, exitCode: failOnError ? 1 : 0 };
  }
  if (failed > 0 && failOnError) return { ...result, exitCode: 1 };
  return { ...result, exitCode: 0 };
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  run().then((res) => {
    console.log(res.summary);
    if (res.error) console.error(res.error);
    process.exit(res.exitCode);
  }).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
