#!/usr/bin/env node

// src/main.js
import { readFileSync, existsSync, appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

// node_modules/@idemcore/sdk/dist/bytes.js
var te = new TextEncoder();
var utf8 = (s) => te.encode(s);
function hex(b) {
  const u = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = "";
  for (const x of u)
    s += x.toString(16).padStart(2, "0");
  return s;
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
var ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
var REV = Object.fromEntries([...ALPHA].map((c, i) => [c, i]));
function b64uDecode(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1)
    throw new Error("not base64url");
  const out = new Uint8Array(Math.floor(s.length * 3 / 4));
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const c = [0, 1, 2, 3].map((k) => i + k < s.length ? REV[s[i + k]] : 0);
    const n = c[0] << 18 | c[1] << 12 | c[2] << 6 | c[3];
    out[o++] = n >> 16 & 255;
    if (i + 2 < s.length)
      out[o++] = n >> 8 & 255;
    if (i + 3 < s.length)
      out[o++] = n & 255;
  }
  return out.slice(0, o);
}
var subtleP = null;
function subtle() {
  if (!subtleP) {
    subtleP = (async () => {
      const g = globalThis.crypto;
      if (g?.subtle)
        return g.subtle;
      const spec = "node:crypto";
      const m = await import(
        /* @vite-ignore */
        /* webpackIgnore: true */
        spec
      );
      return m.webcrypto.subtle;
    })();
  }
  return subtleP;
}
async function sha256(data) {
  return new Uint8Array(await (await subtle()).digest("SHA-256", data));
}
function le64(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, n), true);
  return b;
}

// node_modules/@idemcore/sdk/dist/default-keys.js
var DEFAULT_TRUSTED_KEYS = [
  { kty: "OKP", crv: "Ed25519", x: "AdQX-eipjpmqi4GDvqYHIep2Vb7l5Vas4xncNN453OY", kid: "ed25519:2fab59995ac55e4f" }
];

// node_modules/@idemcore/sdk/dist/keys.js
async function keyIdFor(raw) {
  return "ed25519:" + hex((await sha256(raw)).slice(0, 8));
}
async function importJwk(jwk, source) {
  if (jwk?.kty !== "OKP" || jwk?.crv !== "Ed25519" || typeof jwk.x !== "string")
    throw new Error("not an Ed25519 public JWK");
  const raw = b64uDecode(jwk.x);
  if (raw.length !== 32)
    throw new Error("Ed25519 public key must be 32 bytes");
  const keyId = await keyIdFor(raw);
  if (jwk.kid && jwk.kid !== keyId)
    throw new Error(`kid ${jwk.kid} does not match key bytes (${keyId})`);
  const pk = await (await subtle()).importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  return {
    keyId,
    jwk: { kty: "OKP", crv: "Ed25519", x: jwk.x, kid: keyId },
    source,
    verify: async (sig, msg) => {
      try {
        return await (await subtle()).verify({ name: "Ed25519" }, pk, sig, msg);
      } catch {
        return false;
      }
    }
  };
}
async function importKeySet(data, source) {
  const list = Array.isArray(data) ? data : data && typeof data === "object" && Array.isArray(data.keys) ? data.keys : [data];
  return Promise.all(list.map((j) => importJwk(j, source)));
}

// node_modules/@idemcore/sdk/dist/canonical.js
function cmp(a, b) {
  const A = Array.from(a), B = Array.from(b);
  for (let i = 0; i < Math.min(A.length, B.length); i++) {
    const d = A[i].codePointAt(0) - B[i].codePointAt(0);
    if (d)
      return d;
  }
  return A.length - B.length;
}
function enc(v, path) {
  if (v === null)
    return "null";
  if (typeof v === "boolean")
    return v ? "true" : "false";
  if (typeof v === "string")
    return JSON.stringify(v);
  if (typeof v === "number") {
    if (!(Number.isFinite(v) && Math.floor(v) === v && Math.abs(v) <= 9007199254740991))
      throw new Error(`${path}: only whole numbers are allowed`);
    return String(v);
  }
  if (Array.isArray(v))
    return "[" + v.map((x, i) => enc(x, `${path}[${i}]`)).join(",") + "]";
  if (typeof v === "object") {
    const o = v;
    const keys = Object.keys(o).filter((k) => o[k] !== void 0).sort(cmp);
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + enc(o[k], `${path}.${k}`)).join(",") + "}";
  }
  throw new Error(`${path}: unsupported type`);
}
var canonicalString = (v) => enc(v, "$");
var canonicalBytes = (v) => new TextEncoder().encode(canonicalString(v));

// node_modules/@idemcore/sdk/dist/hash.js
async function taggedHash(tag, ...parts) {
  const chunks = [utf8(`idemcore/${tag}/r1`), new Uint8Array([0])];
  for (const p of parts)
    chunks.push(le64(BigInt(p.length)), p);
  return hex(await sha256(concat(...chunks)));
}
var isWhole = (v) => typeof v === "number" && Number.isFinite(v) && Math.floor(v) === v;
var isSafeWhole = (v) => isWhole(v) && Math.abs(v) <= 9007199254740991;
function tokenBytes(ids) {
  const b = new Uint8Array(ids.length * 4);
  ids.forEach((id, i) => {
    if (!isWhole(id) || id < 0 || id > 4294967295)
      throw new Error(`token id out of range at ${i}`);
    for (let j = 0; j < 4; j++)
      b[i * 4 + j] = Math.floor(id / 2 ** (8 * j)) % 256;
  });
  return b;
}
var promptHash = (messages, salt) => taggedHash("prompt", salt, canonicalBytes(messages));
var tokenHash = (ids, salt) => taggedHash("tokens", salt, tokenBytes(ids));
var WS = /[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/g;
var normalizeText = (s) => s.normalize("NFC").replace(WS, " ").replace(/^ | $/g, "");
var textHash = (text, salt) => taggedHash("text", salt, utf8(normalizeText(text)));
function parseLog(text) {
  const lines = [];
  let all = null;
  text.split(/\r?\n/).forEach((raw, n) => {
    const s = raw.trim();
    if (!s || s.startsWith("#"))
      return;
    const f = s.split(/\s+/);
    if (f[0] === "FORMAT")
      throw new Error("format v2 log: check it with idemcore-verify 0.4.0 or later (this receipt format commits to the earlier log format)");
    if (f[0] === "ALL") {
      if (f.length !== 2 || !/^[0-9a-fA-F]{1,16}$/.test(f[1]))
        throw new Error(`log line ${n + 1}: malformed ALL line`);
      all = f[1].toLowerCase();
      return;
    }
    if (!/^\d+$/.test(f[0]))
      return;
    if (f.length !== 4)
      throw new Error(`log line ${n + 1}: not a public log line (expected 4 fields: pi j h hc)`);
    if (!/^\d+$/.test(f[1]) || !/^[0-9a-fA-F]{1,16}$/.test(f[2]) || !/^[0-9a-fA-F]{1,16}$/.test(f[3]))
      throw new Error(`log line ${n + 1}: malformed field`);
    const ln = { pi: BigInt(f[0]), j: BigInt(f[1]), h: BigInt("0x" + f[2]), hc: BigInt("0x" + f[3]) };
    if (ln.pi >= 2n ** 64n || ln.j >= 2n ** 64n)
      throw new Error(`log line ${n + 1}: index out of range`);
    lines.push(ln);
  });
  return { lines, all };
}
async function chainDigest(lines) {
  let c = await sha256(utf8("idemcore/chain/r1\0"));
  for (const l of lines)
    c = await sha256(concat(c, le64(l.pi), le64(l.j), le64(l.h), le64(l.hc)));
  return hex(c);
}
async function logDigests(text) {
  const p = parseLog(text);
  return { positions: p.lines.length, chain_digest: await chainDigest(p.lines), all_line: p.all };
}

// node_modules/@idemcore/sdk/dist/receipt.js
var RECEIPT_VERSIONS = ["r1", "r2"];
var SIG_DOMAIN = utf8("idemcore-receipt/r1\n");
var HEX64 = /^[0-9a-f]{64}$/;
var HEX16 = /^[0-9a-f]{16}$/;
var COMMON = {
  receipt_version: "str",
  receipt_id: "str",
  issued_at: "str",
  tenant_id: "str",
  model_id: "str",
  weights_hash: "str",
  engine_build: "str",
  privacy: "str",
  prompt_hash: "str",
  params_hash: "str",
  decoding: "str",
  prompt_tokens: "int",
  output_tokens: "int",
  output_token_hash: "str",
  chain_digest: "str",
  log_ref: "str",
  key_id: "str",
  signature: "str"
};
var REQUIRED_R2 = { ...COMMON, variant: "int", chain_check: "str", engine_version: "str" };
var REQUIRED_R1 = { ...COMMON, seed: "int" };
var R1_LEGACY_COUNT = 2;
var OPTIONAL = { finish_reason: "str", request_id: "str", output_text_hash: "str" };
var HASH_FIELDS = ["weights_hash", "prompt_hash", "params_hash", "output_token_hash", "chain_digest"];
var r1Legacy = (r) => Object.keys(r).filter((k) => !(k in REQUIRED_R1) && !(k in OPTIONAL)).sort();
function chainCheckField(r) {
  if (r.receipt_version === "r2")
    return "chain_check";
  for (const k of r1Legacy(r))
    if (typeof r[k] === "string" && HEX16.test(r[k]))
      return k;
  return "chain_check";
}
var result = (level, errors, extra = {}) => ({ level, ok: errors.length === 0, errors, ...extra });
function signingPayload(r) {
  const { signature: _s, ...body } = r;
  return concat(SIG_DOMAIN, canonicalBytes(body));
}
function checkFormat(r) {
  if (typeof r !== "object" || r === null || Array.isArray(r))
    return ["receipt is not an object"];
  const o = r, errs = [];
  if (!RECEIPT_VERSIONS.includes(o.receipt_version))
    return [`unsupported receipt_version ${String(o.receipt_version)}`];
  const REQUIRED = o.receipt_version === "r2" ? REQUIRED_R2 : REQUIRED_R1, CHK = chainCheckField(o);
  for (const [k, t] of Object.entries(REQUIRED)) {
    if (!(k in o))
      errs.push(`missing field ${k}`);
    else if (t === "int" ? !isSafeWhole(o[k]) : typeof o[k] !== "string")
      errs.push(`field ${k} must be ${t}`);
  }
  const extra = Object.keys(o).filter((k) => !(k in REQUIRED) && !(k in OPTIONAL));
  if (o.receipt_version === "r1") {
    const strs = extra.filter((k) => typeof o[k] === "string");
    for (const k of extra)
      if (!strs.includes(k))
        errs.push(`unknown field ${k}`);
    if (strs.length !== R1_LEGACY_COUNT)
      errs.push(`r1 receipt must have ${R1_LEGACY_COUNT} more string fields, found ${strs.length}`);
  } else
    for (const k of extra)
      errs.push(`unknown field ${k}`);
  for (const k of Object.keys(OPTIONAL))
    if (k in o && typeof o[k] !== "string")
      errs.push(`field ${k} must be str`);
  if (errs.length)
    return errs;
  for (const k of HASH_FIELDS)
    if (!HEX64.test(o[k]))
      errs.push(`${k} must be 64 lowercase hex`);
  if ("output_text_hash" in o && !HEX64.test(o.output_text_hash))
    errs.push("output_text_hash must be 64 lowercase hex");
  if (typeof o[CHK] !== "string" || !HEX16.test(o[CHK]))
    errs.push(`${CHK} must be 16 lowercase hex`);
  if (o.privacy !== "hash_only" && o.privacy !== "full")
    errs.push("privacy must be hash_only or full");
  if (o.prompt_tokens < 1 || o.output_tokens < 0)
    errs.push("token counts out of range");
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$/.test(o.issued_at))
    errs.push("issued_at must be RFC 3339 UTC (Z)");
  try {
    canonicalString(o);
  } catch (e) {
    errs.push(e.message);
  }
  return errs;
}
async function verifyL1(r, keys) {
  const errs = checkFormat(r);
  if (errs.length)
    return result("L1", errs);
  const rc = r;
  const pk = keys.find((k) => k.keyId === rc.key_id);
  if (!pk)
    return result("L1", [`unknown key_id ${String(rc.key_id)} (not in the trusted key set)`]);
  let sig;
  try {
    sig = b64uDecode(rc.signature);
  } catch {
    return result("L1", ["signature is not base64url"]);
  }
  if (sig.length !== 64 || !await pk.verify(sig, signingPayload(rc)))
    return result("L1", ["signature does not verify"]);
  return result("L1", [], { key_id: pk.keyId, key_source: pk.source });
}
async function verifyL2(r, logText) {
  let d;
  try {
    d = await logDigests(logText);
  } catch (e) {
    return result("L2", [`log parse error: ${e.message}`]);
  }
  const errs = [];
  if (d.chain_digest !== r.chain_digest)
    errs.push("chain_digest mismatch");
  const want = Number(r.prompt_tokens ?? 0) + Number(r.output_tokens ?? 0);
  if (d.positions !== want)
    errs.push(`log covers ${d.positions} positions, receipt says ${want}`);
  return result("L2", errs, { positions: d.positions, checked: ["chain_digest", "positions"] });
}
async function verifyDisclosure(r, d) {
  const salt = r.privacy === "full" ? new Uint8Array(0) : d.salt;
  if (salt == null)
    return result("disclosure", ["salt required for hash_only receipts"]);
  const errs = [], checked = [];
  if (d.messages !== void 0) {
    checked.push("prompt_hash");
    if (await promptHash(d.messages, salt) !== r.prompt_hash)
      errs.push("prompt_hash mismatch");
  }
  if (d.outputIds !== void 0) {
    checked.push("output_token_hash");
    if (await tokenHash(d.outputIds, salt) !== r.output_token_hash)
      errs.push("output_token_hash mismatch");
  }
  if (d.outputText !== void 0) {
    if (typeof r.output_text_hash !== "string") {
      errs.push("receipt has no output_text_hash; displayed text cannot be bound (use output token ids instead)");
    } else {
      checked.push("output_text_hash");
      if (await textHash(d.outputText, salt) !== r.output_text_hash)
        errs.push("output_text_hash mismatch");
    }
  }
  return result("disclosure", errs, { checked });
}

// node_modules/@idemcore/sdk/dist/verify.js
async function loadKeys(keys) {
  if (keys === void 0 || keys === null)
    return importKeySet(DEFAULT_TRUSTED_KEYS, "bundled");
  if (Array.isArray(keys) && keys.length && typeof keys[0].verify === "function")
    return keys;
  return importKeySet(keys, "caller");
}
async function verifyReceipt(receipt, opts = {}) {
  const levels = {};
  if (opts.checkSignature !== false)
    levels.L1 = await verifyL1(receipt, await loadKeys(opts.keys));
  if (opts.logText !== void 0)
    levels.L2 = await verifyL2(receipt, opts.logText);
  if (opts.messages !== void 0 || opts.outputTokenIds !== void 0 || opts.outputText !== void 0) {
    let salt;
    try {
      salt = typeof opts.salt === "string" ? b64uDecode(opts.salt) : opts.salt;
    } catch {
      levels.disclosure = { level: "disclosure", ok: false, errors: ["salt is not base64url"] };
    }
    if (!levels.disclosure)
      levels.disclosure = await verifyDisclosure(receipt, {
        messages: opts.messages,
        outputIds: opts.outputTokenIds,
        outputText: opts.outputText,
        salt
      });
  }
  const vals = Object.values(levels);
  return { ok: vals.length > 0 && vals.every((l) => l.ok), levels };
}

// node_modules/@idemcore/verify-lib/src/logs.js
var V2 = /^\s*FORMAT\s+idemcore-log\/v2\s*$/m;
async function checkTokenLog(text, opts = {}) {
  if (typeof text === "string" && V2.test(text)) {
    return {
      ok: false,
      format: "v2",
      positions: 0,
      errors: ["format v2 log: check it with the open verifier idemcore-verify 0.4.0 or later"]
    };
  }
  const errors = [];
  let parsed;
  try {
    parsed = parseLog(text);
  } catch (e) {
    return { ok: false, positions: 0, errors: [String(e?.message || e)] };
  }
  if (!parsed.lines.length) errors.push("log has no token positions");
  if (!parsed.all) errors.push("log has no ALL line");
  const digests = await logDigests(text);
  const expected = typeof opts.chainDigest === "string" ? opts.chainDigest.toLowerCase() : void 0;
  if (expected && digests.chain_digest !== expected) {
    errors.push("chain_digest does not match the log");
  }
  return {
    ok: errors.length === 0,
    format: "v1",
    checked: expected ? "chain_digest" : "structure",
    positions: digests.positions ?? parsed.lines.length,
    claimed: parsed.all,
    chain_digest: digests.chain_digest,
    errors
  };
}
function looksLikeTokenLog(text) {
  if (typeof text !== "string") return false;
  if (V2.test(text)) return true;
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (!lines.length) return false;
  const pos = /^\d+\s+\d+\s+[0-9a-fA-F]{16}\s+[0-9a-fA-F]{16}(\s+\S+)*$/;
  const all = /^ALL\s+[0-9a-fA-F]{16}$/;
  return lines.some((l) => pos.test(l) || all.test(l));
}

// node_modules/@idemcore/verify-lib/src/bytes.js
var cryptoObj = globalThis.crypto;
var utf82 = (s) => new TextEncoder().encode(s);
function concat2(...parts) {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function hex2(u) {
  return [...new Uint8Array(u)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function unhex(s) {
  if (typeof s !== "string" || s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error("not hex");
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
async function sha2562(data) {
  const subtle2 = cryptoObj?.subtle;
  if (!subtle2) throw new Error("WebCrypto is not available");
  return new Uint8Array(await subtle2.digest("SHA-256", data));
}

// node_modules/@idemcore/verify-lib/src/audit.js
var EVENT_FIELDS = [
  "tenant_id",
  "seq",
  "ts",
  "event_type",
  "receipt_id",
  "actor",
  "payload",
  "prev_hash"
];
var GENESIS = "0".repeat(64);
var ROOT_DOMAIN = utf82("idemcore-audit-root/r1\n");
async function eventHash(ev) {
  const body = {};
  for (const k of EVENT_FIELDS) body[k] = ev[k] === void 0 ? null : ev[k];
  return hex2(await sha2562(concat2(utf82("idemcore/audit/r1\0"), canonicalBytes(body))));
}
async function verifyEventChain(events) {
  const errors = [];
  let prev = GENESIS;
  let seq = null;
  for (const ev of events) {
    if (seq !== null && ev.seq !== seq + 1) errors.push(`seq gap at ${ev.seq}`);
    if (ev.prev_hash !== prev) errors.push(`prev_hash mismatch at seq ${ev.seq}`);
    if (await eventHash(ev) !== ev.event_hash) errors.push(`event_hash mismatch at seq ${ev.seq}`);
    prev = ev.event_hash;
    seq = ev.seq;
  }
  return errors;
}
async function merkleTreeHash(items) {
  if (items.length === 1) return sha2562(concat2(new Uint8Array([0]), items[0]));
  let k = 1;
  while (k * 2 < items.length) k *= 2;
  return sha2562(
    concat2(new Uint8Array([1]), await merkleTreeHash(items.slice(0, k)), await merkleTreeHash(items.slice(k)))
  );
}
async function merkleRoot(hashesHex) {
  if (!hashesHex.length) return hex2(await sha2562(new Uint8Array(0)));
  return hex2(await merkleTreeHash(hashesHex.map(unhex)));
}
async function verifyRoot(root, events, keys) {
  const errors = [];
  const pk = keys.find((k) => k.keyId === root.key_id);
  const { signature, ...body } = root;
  if (!pk) errors.push(`unknown root key_id ${String(root.key_id)}`);
  else {
    let ok = false;
    try {
      ok = await pk.verify(b64uDecode(String(signature)), concat2(ROOT_DOMAIN, canonicalBytes(body)));
    } catch {
      ok = false;
    }
    if (!ok) errors.push("root signature does not verify");
  }
  if (await merkleRoot(events.map((e) => e.event_hash)) !== root.merkle_root) {
    errors.push("merkle_root mismatch");
  }
  return errors;
}
async function checkAuditBundle(data, keys) {
  const events = Array.isArray(data?.events) ? data.events : [];
  const roots = Array.isArray(data?.roots) ? data.roots : [];
  const errors = [];
  const byTenant = /* @__PURE__ */ new Map();
  for (const ev of events) {
    const t = String(ev.tenant_id);
    if (!byTenant.has(t)) byTenant.set(t, []);
    byTenant.get(t).push(ev);
  }
  for (const [t, evs] of byTenant) {
    evs.sort((a, b) => a.seq - b.seq);
    for (const err of await verifyEventChain(evs)) errors.push(`tenant ${t}: ${err}`);
  }
  for (const root of roots) {
    const evs = events.filter(
      (e) => e.tenant_id === root.tenant_id && e.seq >= Number(root.first_seq) && e.seq <= Number(root.last_seq)
    );
    for (const err of await verifyRoot(root, evs, keys)) errors.push(`root ${String(root.day)}: ${err}`);
  }
  return {
    ok: errors.length === 0 && (events.length > 0 || roots.length > 0),
    events: events.length,
    roots: roots.length,
    errors
  };
}

// node_modules/@idemcore/verify-lib/src/parse.js
var RECEIPT_ID = /rcpt_[0-9a-f]{24}/i;
function isReceipt(obj) {
  return Boolean(
    obj && typeof obj === "object" && typeof obj.receipt_version === "string" && typeof obj.receipt_id === "string" && typeof obj.signature === "string" && typeof obj.model_id === "string"
  );
}
function unwrapReceipt(obj) {
  if (!obj || typeof obj !== "object") return null;
  if (isReceipt(obj)) return { receipt: obj, logText: obj.log_text || obj.logText || void 0 };
  if (isReceipt(obj.receipt)) {
    return {
      receipt: obj.receipt,
      logText: obj.log_text || obj.logText || obj.log || void 0,
      salt: obj.salt ?? obj.idemcore_salt,
      messages: obj.messages,
      outputText: obj.output_text || obj.outputText || obj.text,
      publicJwk: obj.public_jwk || obj.publicJwk
    };
  }
  if (obj.idemcore_receipt && isReceipt(obj.idemcore_receipt)) {
    return {
      receipt: obj.idemcore_receipt,
      logText: obj.log_text || obj.logText,
      salt: obj.idemcore_salt || obj.salt
    };
  }
  return null;
}
function isAuditBundle(obj) {
  if (!obj || typeof obj !== "object") return false;
  const ev = obj.events ?? obj.audit?.events;
  const roots = obj.roots ?? obj.audit?.roots;
  return Array.isArray(ev) && ev.length > 0 || Array.isArray(roots) && roots.length > 0;
}
function auditFrom(obj) {
  if (obj?.audit && isAuditBundle(obj.audit)) return obj.audit;
  if (isAuditBundle(obj)) {
    return {
      events: obj.events || [],
      roots: obj.roots || [],
      receipts: obj.receipts || []
    };
  }
  return null;
}
function receiptsFrom(obj) {
  const out = [];
  const one = unwrapReceipt(obj);
  if (one) out.push(one);
  if (obj && typeof obj === "object" && obj.receipts) {
    const list = Array.isArray(obj.receipts) ? obj.receipts : Object.values(obj.receipts);
    for (const item of list) {
      const u = unwrapReceipt(item) || (isReceipt(item) ? { receipt: item } : null);
      if (u) out.push(u);
    }
  }
  const audit = auditFrom(obj);
  if (audit?.receipts) {
    for (const item of audit.receipts) {
      const u = unwrapReceipt(item) || (isReceipt(item) ? { receipt: item } : null);
      if (u) out.push(u);
    }
  }
  return out;
}
function parseReceiptLink(input) {
  const raw = String(input || "").trim();
  if (!raw) return { ok: false, error: "empty input" };
  if (/^rshare_[0-9a-f]{32}$/i.test(raw)) {
    const shareId = raw.toLowerCase();
    return {
      ok: true,
      kind: "public-share",
      shareId,
      url: `https://api.idemcore.net/v1/public/receipts/${shareId}`,
      includeLog: true,
      needsKey: false
    };
  }
  if (/^rcpt_[0-9a-f]{24}$/i.test(raw)) {
    return {
      ok: true,
      kind: "receipt-id",
      receiptId: raw.toLowerCase(),
      url: `https://api.idemcore.net/v1/receipts/${raw.toLowerCase()}`,
      includeLog: false,
      needsKey: true
    };
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: "not a URL or receipt id" };
  }
  const path = url.pathname.replace(/\/+$/, "") + (url.search || "");
  const host = url.hostname.toLowerCase();
  const allowedHost = host === "api.idemcore.net" || host === "idemcore.net" || host === "www.idemcore.net";
  if (!allowedHost) {
    return { ok: false, error: "link host is not api.idemcore.net or idemcore.net" };
  }
  const pub = url.pathname.match(/\/v1\/public\/receipts\/(rshare_[0-9a-f]{32})(\/log)?\/?$/i);
  if (pub) {
    const shareId = pub[1].toLowerCase();
    const includeLog = Boolean(pub[2]);
    return {
      ok: true,
      kind: includeLog ? "public-share-log" : "public-share",
      shareId,
      includeLog: includeLog || true,
      needsKey: false,
      url: `https://api.idemcore.net/v1/public/receipts/${shareId}`
    };
  }
  const pretty = url.pathname.match(/\/r\/(rshare_[0-9a-f]{32})\/?$/i);
  if (pretty) {
    const shareId = pretty[1].toLowerCase();
    return {
      ok: true,
      kind: "public-share",
      shareId,
      includeLog: true,
      needsKey: false,
      url: `https://api.idemcore.net/v1/public/receipts/${shareId}`
    };
  }
  const shareParam = (url.searchParams.get("share") || url.searchParams.get("share_id") || "").toLowerCase();
  if (/^rshare_[0-9a-f]{32}$/.test(shareParam)) {
    return {
      ok: true,
      kind: "public-share",
      shareId: shareParam,
      includeLog: true,
      needsKey: false,
      url: `https://api.idemcore.net/v1/public/receipts/${shareParam}`
    };
  }
  const m = url.pathname.match(/\/v1\/receipts\/(rcpt_[0-9a-f]{24})(\/log)?\/?$/i);
  if (m) {
    const receiptId = m[1].toLowerCase();
    const includeLog = Boolean(m[2]);
    return {
      ok: true,
      kind: includeLog ? "api-log" : "api-receipt",
      receiptId,
      includeLog,
      needsKey: true,
      url: `https://api.idemcore.net/v1/receipts/${receiptId}${includeLog ? "/log" : ""}`
    };
  }
  const idInQuery = url.searchParams.get("receipt_id") || url.searchParams.get("receipt") || "";
  const idMatch = idInQuery.match(RECEIPT_ID) || url.pathname.match(RECEIPT_ID) || url.hash.match(RECEIPT_ID);
  if (idMatch) {
    const receiptId = idMatch[0].toLowerCase();
    return {
      ok: true,
      kind: "receipt-id",
      receiptId,
      includeLog: false,
      needsKey: true,
      url: `https://api.idemcore.net/v1/receipts/${receiptId}`
    };
  }
  if (url.protocol === "https:" || url.protocol === "http:") {
    return { ok: true, kind: "json-url", url: url.toString(), includeLog: false };
  }
  return { ok: false, error: "unrecognised receipt link" };
}
function parseMaybeJson(text) {
  const s = String(text || "").trim();
  if (!s) return { ok: false, error: "empty" };
  if (s.startsWith("{") || s.startsWith("[")) {
    try {
      return { ok: true, value: JSON.parse(s) };
    } catch (e) {
      return { ok: false, error: `invalid JSON: ${e.message}` };
    }
  }
  return { ok: false, error: "not JSON" };
}
function extractPublicShareLinks(text) {
  const found = [];
  const seen = /* @__PURE__ */ new Set();
  const consider = (value) => {
    const parsed = parseReceiptLink(String(value || "").trim());
    if (!parsed.ok) return;
    if (!String(parsed.kind || "").startsWith("public-share")) return;
    if (seen.has(parsed.url)) return;
    seen.add(parsed.url);
    found.push(parsed);
  };
  const json = parseMaybeJson(text);
  if (json.ok && json.value && typeof json.value === "object") {
    const v = json.value;
    if (Array.isArray(v)) {
      for (const el of v) {
        if (typeof el === "string") consider(el);
        else if (el && typeof el === "object") {
          for (const k of ["url", "share_url", "share", "href", "share_id"]) consider(el[k]);
        }
      }
    } else {
      for (const k of ["url", "share_url", "share", "href", "share_id"]) consider(v[k]);
    }
  }
  for (const line of String(text || "").split("\n")) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    consider(s);
  }
  return found;
}

// node_modules/@idemcore/verify-lib/src/receipts.js
async function loadTrustedKeys(spec, { source = "provided" } = {}) {
  if (spec == null) return importKeySet(DEFAULT_TRUSTED_KEYS, "bundled");
  return importKeySet(spec, source);
}
function levelSummary(result2) {
  const levels = {};
  for (const [name, lvl] of Object.entries(result2.levels || {})) {
    levels[name] = { ok: Boolean(lvl.ok), errors: lvl.errors || [] };
  }
  return levels;
}
async function checkReceipt(receipt, opts = {}) {
  const keys = opts.keys;
  const result2 = await verifyReceipt(receipt, {
    keys,
    logText: opts.logText,
    messages: opts.messages,
    salt: opts.salt,
    outputText: opts.outputText,
    outputTokenIds: opts.outputTokenIds,
    checkSignature: opts.checkSignature
  });
  return {
    ok: Boolean(result2.ok),
    receipt_id: receipt.receipt_id,
    receipt_version: receipt.receipt_version,
    model: receipt.model_id,
    key_id: receipt.key_id,
    issued_at: receipt.issued_at,
    levels: levelSummary(result2),
    errors: Object.values(result2.levels || {}).flatMap((lvl) => lvl.errors || [])
  };
}

// node_modules/@idemcore/verify-lib/src/inspect.js
async function inspectDocument(data, opts = {}) {
  const items = [];
  const keys = opts.keys;
  const receipts = receiptsFrom(data);
  const seen = /* @__PURE__ */ new Set();
  for (const wrap of receipts) {
    const id = wrap.receipt.receipt_id;
    const sig = wrap.receipt.signature;
    const dedupe = `${id}:${sig}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    const verification = await checkReceipt(wrap.receipt, {
      keys,
      logText: wrap.logText || opts.logText,
      messages: wrap.messages || opts.messages,
      salt: wrap.salt || opts.salt,
      outputText: wrap.outputText
    });
    items.push({ kind: "receipt", id, ok: verification.ok, details: verification });
  }
  const audit = auditFrom(data);
  if (audit) {
    const result2 = await checkAuditBundle(audit, keys);
    items.push({
      kind: "audit",
      id: "audit-bundle",
      ok: result2.ok,
      details: result2
    });
  }
  return items;
}
async function inspectText(text, opts = {}) {
  const json = parseMaybeJson(text);
  if (json.ok) {
    if (Array.isArray(json.value)) {
      const items = [];
      for (const el of json.value) {
        items.push(...await inspectDocument(el, opts));
      }
      return items;
    }
    return inspectDocument(json.value, opts);
  }
  const lines = String(text).split("\n");
  const objects = [];
  let jsonl = true;
  for (const line of lines) {
    const s = line.trim();
    if (!s) continue;
    if (!s.startsWith("{") && !s.startsWith("[")) {
      jsonl = false;
      break;
    }
    try {
      objects.push(JSON.parse(s));
    } catch {
      jsonl = false;
      break;
    }
  }
  if (jsonl && objects.length) {
    const items = [];
    for (const el of objects) items.push(...await inspectDocument(el, opts));
    return items;
  }
  if (looksLikeTokenLog(text)) {
    const result2 = await checkTokenLog(text);
    return [{ kind: "log", id: "token-log", ok: result2.ok, details: result2 }];
  }
  return [{ kind: "unknown", id: "input", ok: false, details: { errors: [json.error || "unrecognised input"] } }];
}

// src/glob.js
import { readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
var SKIP = /* @__PURE__ */ new Set([
  ".git",
  ".venv",
  "node_modules",
  "dist",
  "build",
  ".pytest_cache",
  "__pycache__"
]);
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function globToRegExp(glob) {
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
function parseGlobs(input) {
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
function walkFiles(root) {
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
function matchFiles(root, globInput) {
  const patterns = parseGlobs(globInput).map((g) => globToRegExp(g.replace(/^\.\//, "")));
  const files = [];
  for (const full of walkFiles(root)) {
    const rel = relative(root, full).split(sep).join("/");
    if (patterns.some((re) => re.test(rel))) files.push({ full, rel });
  }
  return files.sort((a, b) => a.rel.localeCompare(b.rel));
}

// src/main.js
function boolInput(v, fallback = true) {
  if (v === void 0 || v === null || v === "") return fallback;
  const s = String(v).trim().toLowerCase();
  if (["false", "0", "no", "off"].includes(s)) return false;
  if (["true", "1", "yes", "on"].includes(s)) return true;
  return fallback;
}
function writeOutput(env, name, value) {
  const file = env.GITHUB_OUTPUT;
  if (file) appendFileSync(file, `${name}=${value}
`);
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
      details: { errors: ["fetch is not available to resolve public share links"] }
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
          details: { errors: [`public share ${link.url} returned HTTP ${res.status}`] }
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
          details: { errors: ["the public share response did not contain a signed receipt"] }
        });
      } else {
        items.push(...found);
      }
    } catch (e) {
      items.push({
        kind: "public-share",
        id: link.shareId,
        ok: false,
        details: { errors: [e.message] }
      });
    }
  }
  return items;
}
async function run(env = process.env, cwd = process.cwd(), opts = {}) {
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
    if (file.rel.endsWith("SOURCE.md") || file.rel.endsWith("package-lock.json")) continue;
    let items = await inspectText(text, { keys });
    let useful = items.filter((it) => it.kind !== "unknown");
    if (!useful.length) useful = await inspectPublicShares(text, keys, fetchImpl);
    if (!useful.length) continue;
    for (const it of useful) {
      rows.push({
        file: file.rel,
        kind: it.kind,
        id: it.id,
        ok: it.ok,
        errors: it.details?.errors || []
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
    `Checked **${checked}** \xB7 passed **${passed}** \xB7 failed **${failed}**.`,
    "",
    "These checks run offline. No API key is used.",
    ""
  ];
  const summary = tableLines.join("\n");
  writeSummary(env, summary);
  writeOutput(env, "passed", String(passed));
  writeOutput(env, "failed", String(failed));
  writeOutput(env, "checked", String(checked));
  const result2 = { passed, failed, checked, rows, summary };
  if (requireFiles && checked === 0) {
    result2.error = `no receipts, token logs, or audit exports matched ${glob}`;
    return { ...result2, exitCode: failOnError ? 1 : 0 };
  }
  if (failed > 0 && failOnError) return { ...result2, exitCode: 1 };
  return { ...result2, exitCode: 0 };
}
var invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
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
export {
  run
};
