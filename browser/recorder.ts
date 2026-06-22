/**
 * The browser session recorder. Mirrors provenance/recorder.py: it maintains the
 * document state as edits arrive, validates each edit, and records hash-chained
 * events. The events replay to the exact recorded document, so the sealed certificate
 * cannot claim a document the events do not produce.
 *
 * In a real browser these methods are driven by editor events (keydown, paste, etc.).
 * Here they are a clean API the future UI calls; the UI is a later commit.
 *
 * Sealing signs with Ed25519 via WebCrypto, the same algorithm the Python signer uses,
 * so a certificate sealed here verifies with the Python public key.
 */
import { EventLog, textHashOf, type Event, type EventType } from "./log.ts";
import { canonicalBytes } from "./canonical.ts";

export const CERTIFICATE_VERSION = 1;

export interface Certificate {
  version: number;
  document_hash: string;
  sealed_at: number;
  log: { events: Event[]; head: string };
  signature: string;
}

export class RecorderError extends Error {}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export class SessionRecorder {
  private log = new EventLog();
  private doc = "";
  private lastTs = 0;
  private seq = 0;
  private started = false;
  private ended = false;

  get document(): string {
    return this.doc;
  }

  get hasEnded(): boolean {
    return this.ended;
  }

  private checkOpen(): void {
    if (!this.started) throw new RecorderError("session has not started");
    if (this.ended) throw new RecorderError("session has already ended");
  }

  private checkTime(ts: number): void {
    if (ts < this.lastTs) {
      throw new RecorderError(`timestamp moved backward: ${ts} < ${this.lastTs}`);
    }
  }

  private async appendEvent(
    type: EventType,
    timestamp: number,
    position: number,
    text: string,
  ): Promise<void> {
    const event: Event = {
      seq: this.seq,
      type,
      timestamp,
      position,
      length: text.length,
      text_hash: await textHashOf(text),
    };
    await this.log.append(event);
    this.seq += 1;
    this.lastTs = timestamp;
  }

  async start(timestamp: number): Promise<void> {
    if (this.started) throw new RecorderError("session already started");
    await this.appendEvent("session_start", timestamp, 0, "");
    this.started = true;
  }

  async insert(timestamp: number, position: number, text: string): Promise<void> {
    this.checkOpen();
    this.checkTime(timestamp);
    if (position < 0 || position > this.doc.length) {
      throw new RecorderError(`insert position ${position} out of range 0..${this.doc.length}`);
    }
    if (text === "") throw new RecorderError("insert text must be non-empty");
    this.doc = this.doc.slice(0, position) + text + this.doc.slice(position);
    await this.appendEvent("insert", timestamp, position, text);
  }

  async paste(timestamp: number, position: number, text: string): Promise<void> {
    this.checkOpen();
    this.checkTime(timestamp);
    if (position < 0 || position > this.doc.length) {
      throw new RecorderError(`paste position ${position} out of range 0..${this.doc.length}`);
    }
    if (text === "") throw new RecorderError("paste text must be non-empty");
    this.doc = this.doc.slice(0, position) + text + this.doc.slice(position);
    await this.appendEvent("paste", timestamp, position, text);
  }

  async delete(timestamp: number, position: number, length: number): Promise<void> {
    this.checkOpen();
    this.checkTime(timestamp);
    if (length <= 0) throw new RecorderError("delete length must be positive");
    if (position < 0 || position + length > this.doc.length) {
      throw new RecorderError(
        `delete range ${position}..${position + length} out of document length ${this.doc.length}`,
      );
    }
    this.doc = this.doc.slice(0, position) + this.doc.slice(position + length);
    await this.appendEvent("delete", timestamp, position, "x".repeat(length) /* length only */);
  }

  async end(timestamp: number): Promise<void> {
    this.checkOpen();
    this.checkTime(timestamp);
    await this.appendEvent("session_end", timestamp, this.doc.length, "");
    this.ended = true;
  }

  /**
   * Seal the ended session into a signed certificate using this recorder's own
   * reconstructed document, so the certificate is consistent with the events by
   * construction. privateKey is a WebCrypto Ed25519 CryptoKey.
   */
  async sealWith(privateKey: CryptoKey, sealedAt: number): Promise<Certificate> {
    if (!this.ended) throw new RecorderError("cannot seal a session that has not ended");

    const body = {
      version: CERTIFICATE_VERSION,
      document_hash: await textHashOf(this.doc),
      sealed_at: sealedAt,
      log: this.log.toDict(),
    };
    const sig = await crypto.subtle.sign("Ed25519", privateKey, canonicalBytes(body));
    return { ...body, signature: toHex(sig) };
  }
}
