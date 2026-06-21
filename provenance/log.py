"""
The tamper-evident event log.

A writing session is a sequence of events (insert, delete, paste, ...). Each event
carries the hash of the previous event, forming a chain. Altering, inserting, or
removing any event changes its hash and breaks every link after it, so a verifier
can detect tampering by recomputing the chain.

Two design rules make this portable and trustworthy:

1. Canonical serialization. Events are hashed over a byte-exact JSON encoding with
   sorted keys and no incidental whitespace. The browser capture layer (TypeScript,
   later) must produce byte-identical bytes, so the rule is: UTF-8, sorted keys,
   compact separators, no floats in hashed fields. Hash the bytes, never a language's
   in-memory object.

2. The chain starts from a fixed genesis hash, so an empty log has a well-defined
   head and the first real event is chained to something deterministic.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Fixed starting point for every chain. The first event's prev_hash is this.
GENESIS_HASH = "0" * 64


class EventType(str, Enum):
    INSERT = "insert"   # text typed/inserted at a position
    DELETE = "delete"   # text removed
    PASTE = "paste"     # text pasted from outside (first-class: the key signal)
    SESSION_START = "session_start"
    SESSION_END = "session_end"


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """Byte-exact JSON for hashing. Sorted keys, compact, UTF-8.

    This function is the contract the future browser layer must match exactly. Any
    divergence here means a certificate sealed in the browser would fail server
    verification, so it is deliberately simple and strict.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Event:
    """One recorded edit. Immutable once created.

    seq:        position in the session, starting at 0
    type:       what happened
    timestamp:  client clock, milliseconds since epoch (when the edit occurred)
    position:   character offset in the document where it happened
    length:     number of characters affected
    text_hash:  sha256 of the affected text, NOT the text itself

    We hash the affected text rather than storing it in the chain so the chain can be
    shared/verified without leaking the full manuscript. The full text lives in the
    playback record, which the writer chooses to reveal. The chain proves structure
    and timing; the playback reveals content.
    """

    seq: int
    type: EventType
    timestamp: int
    position: int
    length: int
    text_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "type": self.type.value,
            "timestamp": self.timestamp,
            "position": self.position,
            "length": self.length,
            "text_hash": self.text_hash,
        }

    def hashed_with(self, prev_hash: str) -> str:
        """The chain hash for this event given the previous event's hash."""
        payload = {"prev_hash": prev_hash, "event": self.to_dict()}
        return sha256_hex(canonical_bytes(payload))

    @staticmethod
    def text_hash_of(text: str) -> str:
        """Helper: hash document text for the text_hash field."""
        return sha256_hex(text.encode("utf-8"))


@dataclass
class EventLog:
    """An append-only, hash-chained sequence of events."""

    _events: list[Event] = field(default_factory=list)
    _hashes: list[str] = field(default_factory=list)  # chain hash per event

    def append(self, event: Event) -> None:
        """Add an event, enforcing sequential seq and extending the chain."""
        expected_seq = len(self._events)
        if event.seq != expected_seq:
            raise ValueError(
                f"out-of-order event: expected seq {expected_seq}, got {event.seq}"
            )
        prev = self._hashes[-1] if self._hashes else GENESIS_HASH
        self._hashes.append(event.hashed_with(prev))
        self._events.append(event)

    @property
    def head(self) -> str:
        """The current chain head: hash of the last event, or genesis if empty."""
        return self._hashes[-1] if self._hashes else GENESIS_HASH

    @property
    def events(self) -> list[Event]:
        return list(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def verify(self) -> bool:
        """Recompute the chain from scratch and confirm it matches.

        Returns False if any event was altered, inserted, or removed in a way that
        breaks the linkage. This is what a verifier runs to detect tampering.
        """
        prev = GENESIS_HASH
        for i, event in enumerate(self._events):
            if event.seq != i:
                return False
            expected = event.hashed_with(prev)
            if expected != self._hashes[i]:
                return False
            prev = expected
        return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize the whole log (events + head) for sealing into a certificate."""
        return {
            "events": [e.to_dict() for e in self._events],
            "head": self.head,
        }

    @classmethod
    def from_events(cls, events: list[Event]) -> "EventLog":
        """Rebuild a log from a list of events, recomputing the chain."""
        log = cls()
        for e in events:
            log.append(e)
        return log
