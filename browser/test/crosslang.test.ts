/**
 * The cross-language proof. This is the test that actually matters for the product:
 * a certificate sealed by the TypeScript recorder must verify with the Python CLI.
 *
 * It records a session, generates an Ed25519 keypair via WebCrypto, seals the
 * certificate, writes the cert JSON and the public key hex to disk, then shells out
 * to the Python `provenance verify` command and asserts it reports VALID.
 *
 * If this passes, the byte-level agreement between the two languages is real, not
 * assumed: Python independently recomputed the chain and checked the signature over
 * bytes that TypeScript produced.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { SessionRecorder } from "../recorder.ts";

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

test("certificate sealed in TypeScript verifies with the Python CLI", async () => {
  const r = new SessionRecorder();
  await r.start(0);
  await r.insert(5000, 0, "Written in the browser layer.");
  await r.paste(9000, 29, " (pasted bit)");
  await r.end(60000);

  // Ed25519 keypair via WebCrypto, the same algorithm Python uses.
  const pair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const cert = await r.sealWith(pair.privateKey, 61000);

  // Export the raw public key to hex, the form the Python CLI expects.
  const rawPub = await crypto.subtle.exportKey("raw", pair.publicKey);
  const pubHex = toHex(rawPub);

  const dir = mkdtempSync(join(tmpdir(), "prov-xlang-"));
  const certPath = join(dir, "c.cert.json");
  const keyPath = join(dir, "c.key.hex");
  writeFileSync(certPath, JSON.stringify(cert));
  writeFileSync(keyPath, pubHex);

  // Shell out to the Python verifier. Repo root is two levels up from test/.
  const repoRoot = join(import.meta.dirname, "..", "..");
  const output = execFileSync(
    "python3",
    ["-m", "provenance.cli", "verify", certPath, keyPath],
    { cwd: repoRoot, env: { ...process.env, PYTHONPATH: "." }, encoding: "utf-8" },
  );

  assert.match(output, /VALID/);
  assert.doesNotMatch(output, /INVALID/);
});
