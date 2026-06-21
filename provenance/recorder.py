"""
The session recorder.

Sits between live edits and the trust core. Its job is to turn a stream of edits
into an event log that is not just cryptographically intact but actually consistent:
the events, replayed in order, reconstruct the exact document the certificate will
claim. A log that verifies cryptographically but does not reproduce its own document
would be a certificate that lies, which is worse than none.

So the recorder maintains the document state as it records, applies each edit to that
state, and records the event with a hash of the resulting text region. At seal time
the reconstructed document must hash to the same value the certificate stores. The
recorder enforces:

  - time does not move backward (timestamps are non-decreasing)
  - edits apply at valid positions in the current document
  - paste is recorded as paste, not disguised as typing

The recorder produces an EventLog (from the trust core). Sealing is still done by the
Signer, so the recorder holds no keys and makes no trust claims on its own.
"""
from __future__ import annotations

from dataclasses import dataclass

from .log import Event, EventLog, EventType


class RecorderError(ValueError):
    """Raised when an edit would make the session inconsistent."""


@dataclass
class _Edit:
    """A raw edit handed to the recorder, before it becomes a hashed Event."""

    type: EventType
    timestamp: int
    position: int
    text: str  # inserted/pasted text, or the text being deleted


class SessionRecorder:
    """Records a writing session into a consistent, hash-chained event log."""

    def __init__(self) -> None:
        self._log = EventLog()
        self._doc = ""           # current reconstructed document text
        self._last_ts = 0        # for monotonic time enforcement
        self._seq = 0
        self._started = False
        self._ended = False

    @property
    def document(self) -> str:
        return self._doc

    @property
    def log(self) -> EventLog:
        return self._log

    def _check_open(self) -> None:
        if not self._started:
            raise RecorderError("session has not started")
        if self._ended:
            raise RecorderError("session has already ended")

    def _check_time(self, timestamp: int) -> None:
        if timestamp < self._last_ts:
            raise RecorderError(
                f"timestamp moved backward: {timestamp} < {self._last_ts}"
            )

    def _append(self, etype: EventType, timestamp: int, position: int, text: str) -> None:
        event = Event(
            seq=self._seq,
            type=etype,
            timestamp=timestamp,
            position=position,
            length=len(text),
            text_hash=Event.text_hash_of(text),
        )
        self._log.append(event)
        self._seq += 1
        self._last_ts = timestamp

    def start(self, timestamp: int) -> None:
        if self._started:
            raise RecorderError("session already started")
        self._append(EventType.SESSION_START, timestamp, 0, "")
        self._started = True

    def insert(self, timestamp: int, position: int, text: str) -> None:
        """Record typed/inserted text at a position in the current document."""
        self._check_open()
        self._check_time(timestamp)
        if position < 0 or position > len(self._doc):
            raise RecorderError(
                f"insert position {position} out of range 0..{len(self._doc)}"
            )
        if text == "":
            raise RecorderError("insert text must be non-empty")
        self._doc = self._doc[:position] + text + self._doc[position:]
        self._append(EventType.INSERT, timestamp, position, text)

    def paste(self, timestamp: int, position: int, text: str) -> None:
        """Record pasted text. Same effect on the document as insert, but recorded
        as PASTE so the verifier and playback can flag externally sourced text."""
        self._check_open()
        self._check_time(timestamp)
        if position < 0 or position > len(self._doc):
            raise RecorderError(
                f"paste position {position} out of range 0..{len(self._doc)}"
            )
        if text == "":
            raise RecorderError("paste text must be non-empty")
        self._doc = self._doc[:position] + text + self._doc[position:]
        self._append(EventType.PASTE, timestamp, position, text)

    def delete(self, timestamp: int, position: int, length: int) -> None:
        """Record removal of `length` characters starting at `position`."""
        self._check_open()
        self._check_time(timestamp)
        if length <= 0:
            raise RecorderError("delete length must be positive")
        if position < 0 or position + length > len(self._doc):
            raise RecorderError(
                f"delete range {position}..{position + length} out of document "
                f"length {len(self._doc)}"
            )
        removed = self._doc[position : position + length]
        self._doc = self._doc[:position] + self._doc[position + length :]
        self._append(EventType.DELETE, timestamp, position, removed)

    def end(self, timestamp: int) -> None:
        self._check_open()
        self._check_time(timestamp)
        self._append(EventType.SESSION_END, timestamp, len(self._doc), "")
        self._ended = True

    @property
    def ended(self) -> bool:
        return self._ended

    def paste_ratio(self) -> float:
        """Fraction of the final document's characters that arrived via paste.

        A blunt but useful signal: a document that is mostly pasted text is exactly
        what a reviewer wants flagged. Computed from recorded events, not the text.
        """
        inserted = 0
        pasted = 0
        for e in self._log.events:
            if e.type is EventType.INSERT:
                inserted += e.length
            elif e.type is EventType.PASTE:
                pasted += e.length
        total = inserted + pasted
        if total == 0:
            return 0.0
        return pasted / total

    def seal_with(self, signer, sealed_at: int):
        """Seal this session into a certificate using the recorder's OWN
        reconstructed document, so the certificate's document hash is always
        consistent with the recorded events by construction. The session must have
        ended first, so the certificate covers a complete session.

        Imported lazily to keep the recorder independent of the certificate module's
        crypto dependency at import time.
        """
        if not self._ended:
            raise RecorderError("cannot seal a session that has not ended")
        return signer.seal(self._log, final_text=self._doc, sealed_at=sealed_at)
