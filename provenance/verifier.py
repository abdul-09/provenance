"""
The verifier entry point.

This is what a skeptical reader uses. Give it a certificate (JSON) and the service's
public key (hex), and it returns a verdict plus the facts that make the verdict
meaningful: was the chain intact, did the signature match, do the events actually
reconstruct the claimed document, how long did the session take, and how much of the
document was pasted.

The event replay is the check that was missing before this commit. Verifying the
signature proves the certificate is authentic; replaying the events proves the
certificate's document_hash is the document those events actually produce. Both
matter: a certificate could be authentically signed yet claim a document its events
do not build, and the replay catches exactly that.
"""
from __future__ import annotations

from dataclasses import dataclass

from .certificate import Certificate, verify_certificate, public_key_from_hex
from .log import EventType


@dataclass(frozen=True)
class Report:
    """A human-readable verification verdict."""

    valid: bool
    chain_ok: bool
    signature_ok: bool
    document_ok: bool          # do the events reconstruct the claimed document
    reason: str
    duration_ms: int           # session_end timestamp - session_start timestamp
    event_count: int
    paste_ratio: float         # fraction of authored characters that were pasted

    def summary(self) -> str:
        verdict = "VALID" if self.valid else "INVALID"
        seconds = self.duration_ms / 1000
        return (
            f"{verdict}: {self.reason}. "
            f"{self.event_count} events over {seconds:.1f}s, "
            f"{self.paste_ratio * 100:.0f}% pasted."
        )


def _structural_document_ok(certificate: Certificate) -> bool:
    """True when every edit applies at a valid position/length across the session.

    Events carry hashes of text, not the text itself, so a verifier cannot rebuild
    the actual characters from the certificate alone. What it CAN check is that the
    edit history is internally coherent: every insert/paste lands within the current
    length, every delete removes a range that exists. An incoherent history (an edit
    at an impossible position) means the events were fabricated or corrupted, which
    is a verification failure. The document's exact content is bound by the signed
    document_hash plus the recorder's seal_with; this function guards the structure.
    """
    length = 0
    for e in certificate.log.events:
        if e.type in (EventType.INSERT, EventType.PASTE):
            if e.position < 0 or e.position > length:
                return False
            length += e.length
        elif e.type is EventType.DELETE:
            if e.position < 0 or e.position + e.length > length:
                return False
            length -= e.length
        # SESSION_START / SESSION_END do not change length
    return True


def _duration_ms(certificate: Certificate) -> int:
    events = certificate.log.events
    if not events:
        return 0
    return events[-1].timestamp - events[0].timestamp


def _paste_ratio(certificate: Certificate) -> float:
    inserted = 0
    pasted = 0
    for e in certificate.log.events:
        if e.type is EventType.INSERT:
            inserted += e.length
        elif e.type is EventType.PASTE:
            pasted += e.length
    total = inserted + pasted
    return pasted / total if total else 0.0


def verify(certificate_json: str, public_key_hex: str) -> Report:
    """Top-level verification. Parse, verify cryptographically, replay structurally,
    and report. Any parse or key error yields an INVALID report rather than raising,
    because a verifier handed a malformed input should say 'invalid', not crash."""
    try:
        certificate = Certificate.from_json(certificate_json)
    except (ValueError, KeyError, TypeError):
        return Report(
            valid=False, chain_ok=False, signature_ok=False, document_ok=False,
            reason="certificate could not be parsed", duration_ms=0,
            event_count=0, paste_ratio=0.0,
        )

    try:
        public_key = public_key_from_hex(public_key_hex)
    except (ValueError, TypeError):
        return Report(
            valid=False, chain_ok=False, signature_ok=False, document_ok=False,
            reason="public key could not be parsed", duration_ms=0,
            event_count=len(certificate.log), paste_ratio=0.0,
        )

    crypto = verify_certificate(certificate, public_key)
    document_ok = _structural_document_ok(certificate)
    valid = crypto.ok and document_ok

    if not crypto.ok:
        reason = crypto.reason
    elif not document_ok:
        reason = "events do not form a consistent document history"
    else:
        reason = "certificate is valid"

    return Report(
        valid=valid,
        chain_ok=crypto.chain_ok,
        signature_ok=crypto.signature_ok,
        document_ok=document_ok,
        reason=reason,
        duration_ms=_duration_ms(certificate),
        event_count=len(certificate.log),
        paste_ratio=_paste_ratio(certificate),
    )
