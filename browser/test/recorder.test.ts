/**
 * Unit tests for the TypeScript recorder. These mirror the Python recorder tests so
 * the two implementations enforce the same rules. Validation parity matters: if the
 * browser accepted an edit the Python recorder would reject, the two could diverge.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SessionRecorder, RecorderError } from "../recorder.ts";

test("reconstructs document from inserts", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await r.insert(2, 0, "Hello");
  await r.insert(3, 5, " world");
  assert.equal(r.document, "Hello world");
});

test("insert in the middle", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await r.insert(2, 0, "Helo");
  await r.insert(3, 2, "l");
  assert.equal(r.document, "Hello");
});

test("delete removes text", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await r.insert(2, 0, "Hello world");
  await r.delete(3, 5, 6);
  assert.equal(r.document, "Hello");
});

test("paste inserts and is allowed", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await r.insert(2, 0, "A ");
  await r.paste(3, 2, "pasted block");
  assert.equal(r.document, "A pasted block");
});

test("cannot edit before start", async () => {
  const r = new SessionRecorder();
  await assert.rejects(() => r.insert(1, 0, "x"), RecorderError);
});

test("cannot edit after end", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await r.insert(2, 0, "x");
  await r.end(3);
  await assert.rejects(() => r.insert(4, 0, "y"), RecorderError);
});

test("time cannot move backward", async () => {
  const r = new SessionRecorder();
  await r.start(1000);
  await assert.rejects(() => r.insert(999, 0, "x"), /moved backward/);
});

test("insert out of range rejected", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await assert.rejects(() => r.insert(2, 5, "x"), /out of range/);
});

test("empty insert rejected", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await assert.rejects(() => r.insert(2, 0, ""), /non-empty/);
});

test("delete out of range rejected", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await r.insert(2, 0, "abc");
  await assert.rejects(() => r.delete(3, 0, 99), /out of document length/);
});

test("cannot seal before end", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await r.insert(2, 0, "x");
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  await assert.rejects(() => r.sealWith(pair.privateKey, 10), /has not ended/);
});

test("double start rejected", async () => {
  const r = new SessionRecorder();
  await r.start(1);
  await assert.rejects(() => r.start(2), /already started/);
});
