/**
 * The hash-chained event log, TypeScript side. Mirrors provenance/log.py.
 *
 * Each event is hashed together with the previous event's hash, forming a chain that
 * breaks if any event is altered. The hashing must match Python byte-for-byte, which
 * is why it routes through canonicalBytes and the shared sha256.
 *
 * sha256 is async here because the browser's WebCrypto SubtleDigest is async. In Node
 * tests we use the same WebCrypto API (globalThis.crypto.subtle), so the code path is
 * identical to the browser.
 */
import { canonicalBytes } from "./canonical.ts";

export const GENESIS_HASH = "0".repeat(64);

export type EventType =
  | "session_start"
  | "session_end"
  | "insert"
  | "delete"
  | "paste";

export interface Event {
  seq: number;
  type: EventType;
  timestamp: number;
  position: number;
  length: number;
  text_hash: string;
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}

export async function textHashOf(text: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(text));
}

/** The chain hash for an event given the previous event's hash. Mirrors
 * Event.hashed_with in Python: hash of canonical {"prev_hash", "event"}. */
export async function hashedWith(event: Event, prevHash: string): Promise<string> {
  const payload = {
    prev_hash: prevHash,
    event: {
      seq: event.seq,
      type: event.type,
      timestamp: event.timestamp,
      position: event.position,
      length: event.length,
      text_hash: event.text_hash,
    },
  };
  return sha256Hex(canonicalBytes(payload));
}

export class EventLog {
  private events: Event[] = [];
  private hashes: string[] = [];

  async append(event: Event): Promise<void> {
    const expectedSeq = this.events.length;
    if (event.seq !== expectedSeq) {
      throw new Error(
        `out-of-order event: expected seq ${expectedSeq}, got ${event.seq}`,
      );
    }
    const prev = this.hashes.length ? this.hashes[this.hashes.length - 1] : GENESIS_HASH;
    this.hashes.push(await hashedWith(event, prev));
    this.events.push(event);
  }

  get head(): string {
    return this.hashes.length ? this.hashes[this.hashes.length - 1] : GENESIS_HASH;
  }

  get length(): number {
    return this.events.length;
  }

  toDict(): { events: Event[]; head: string } {
    return { events: this.events.map((e) => ({ ...e })), head: this.head };
  }
}
