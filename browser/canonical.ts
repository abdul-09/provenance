/**
 * Canonical serialization, the byte-exact match to the Python side's canonical_bytes.
 *
 * The contract: sorted object keys, compact separators (no spaces), UTF-8, non-ASCII
 * left as real characters (Python's ensure_ascii=False). If these bytes differ from
 * Python's by even one character, a certificate sealed here will fail the Python
 * verifier, so this file is the most safety-critical part of the browser layer and is
 * checked against known-good vectors generated from Python.
 *
 * JSON.stringify is not enough on its own: it does not sort keys. So we recursively
 * rebuild objects with sorted keys, then stringify with no whitespace. JSON.stringify
 * already produces compact output and escapes the same control characters Python does
 * for the value types we use (strings, ints, arrays, objects), and it leaves printable
 * non-ASCII as-is, matching ensure_ascii=False.
 */

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

function sortKeysDeep(value: Json): Json {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === "object") {
    const out: { [k: string]: Json } = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = sortKeysDeep(value[key]);
    }
    return out;
  }
  return value;
}

/** Canonical JSON string. Matches Python canonical_bytes decoded as UTF-8. */
export function canonicalString(obj: Json): string {
  return JSON.stringify(sortKeysDeep(obj));
}

/** Canonical bytes, UTF-8 encoded. Matches Python canonical_bytes exactly. */
export function canonicalBytes(obj: Json): Uint8Array {
  return new TextEncoder().encode(canonicalString(obj));
}
