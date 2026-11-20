import { readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

const SKIP = new Set([
  ".git",
  ".venv",
  "node_modules",
  "dist",
  "build",
  ".pytest_cache",
  "__pycache__",
]);

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function globToRegExp(glob) {
  const s = glob.replace(/\\/g, "/");
  let out = "^";
  let i = 0;
  while (i < s.length) {
    if (s.startsWith("**/", i)) {
      out += ".*";
      i += 3;
      continue;
    }
    if (s.startsWith("**", i) && i + 2 === s.length) {
      out += ".*";
      i += 2;
      continue;
    }
    if (s[i] === "*") {
      out += "[^/]*";
      i += 1;
      continue;
    }
    if (s[i] === "?") {
      out += "[^/]";
      i += 1;
      continue;
    }
    if (s[i] === "{") {
      const end = s.indexOf("}", i + 1);
      if (end === -1) throw new Error("unclosed brace in glob");
      const alts = s.slice(i + 1, end).split(",").map(escapeRegExp);
      out += "(?:" + alts.join("|") + ")";
      i = end + 1;
      continue;
    }
    out += escapeRegExp(s[i]);
    i += 1;
  }
  return new RegExp(out + "$");
}

export function parseGlobs(input) {
  // Split on commas that are not inside a brace group, so
  // **/*.{json,log} stays one pattern and "a.json, b.log" is two.
  const raw = String(input || "");
  const parts = [];
  let buf = "";
  let depth = 0;
  for (const ch of raw) {
    if (ch === "{") depth += 1;
    if (ch === "}") depth = Math.max(0, depth - 1);
    if (ch === "," && depth === 0) {
      if (buf.trim()) parts.push(buf.trim());
      buf = "";
      continue;
    }
    buf += ch;
  }
  if (buf.trim()) parts.push(buf.trim());
  return parts;
}

export function walkFiles(root) {
  const out = [];
  function rec(dir) {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (SKIP.has(ent.name) || ent.name.startsWith(".git")) continue;
      const full = join(dir, ent.name);
      if (ent.isDirectory()) rec(full);
      else if (ent.isFile()) out.push(full);
    }
  }
  rec(root);
  return out;
}

export function matchFiles(root, globInput) {
  const patterns = parseGlobs(globInput).map((g) => globToRegExp(g.replace(/^\.\//, "")));
  const files = [];
  for (const full of walkFiles(root)) {
    const rel = relative(root, full).split(sep).join("/");
    if (patterns.some((re) => re.test(rel))) files.push({ full, rel });
  }
  return files.sort((a, b) => a.rel.localeCompare(b.rel));
}
