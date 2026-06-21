"""
The proof tests. These are the product's credibility expressed as assertions: a
certificate must detect every form of tampering. If any of these fail, the whole
premise (a trustworthy provenance certificate) collapses.
"""
from __future__ import annotations

import dataclasses

import pytest

from provenance.log import (
    GENESIS_HASH,
    Event,
    EventLog,
    EventType,
    canonical_bytes,
    sha256_hex,
)
from provenance.certificate import (
    Certificate,
    Signer,
    verify_certificate,
)


def ev(seq: int, etype: EventType = EventType.INSERT, ts: int = 1000, text: str = "x") -> Event:
    return Event(
        seq=seq,
        type=etype,
        timestamp=ts + seq,
        position=seq,
        length=len(text),
        text_hash=Event.text_hash_of(text),
    )


def build_log(n: int = 5) -> EventLog:
    log = EventLog()
    for i in range(n):
        log.append(ev(i))
    return log


# --- canonical serialization ----------------------------------------------------

class TestCanonical:
    def test_sorted_keys_and_compact(self) -> None:
        b = canonical_bytes({"b": 1, "a": 2})
        assert b == b'{"a":2,"b":1}'

    def test_utf8_non_ascii_preserved(self) -> None:
        b = canonical_bytes({"k": "café"})
        assert "café" in b.decode("utf-8")

    def test_deterministic(self) -> None:
        obj = {"z": [1, 2], "a": {"n": 3}}
        assert canonical_bytes(obj) == canonical_bytes(dict(obj))


# --- the hash chain --------------------------------------------------------------

class TestChain:
    def test_empty_log_head_is_genesis(self) -> None:
        assert EventLog().head == GENESIS_HASH

    def test_first_event_chains_to_genesis(self) -> None:
        log = EventLog()
        e = ev(0)
        log.append(e)
        assert log.head == e.hashed_with(GENESIS_HASH)

    def test_append_enforces_sequential_seq(self) -> None:
        log = EventLog()
        log.append(ev(0))
        with pytest.raises(ValueError, match="out-of-order"):
            log.append(ev(2))  # skipped seq 1

    def test_valid_log_verifies(self) -> None:
        assert build_log(10).verify() is True

    def test_head_changes_with_each_event(self) -> None:
        log = EventLog()
        heads = [log.head]
        for i in range(3):
            log.append(ev(i))
            heads.append(log.head)
        assert len(set(heads)) == 4  # all distinct

    def test_len(self) -> None:
        assert len(build_log(7)) == 7

    def test_from_events_rebuilds_identical_chain(self) -> None:
        original = build_log(5)
        rebuilt = EventLog.from_events(original.events)
        assert rebuilt.head == original.head
        assert rebuilt.verify()


# --- tamper detection (the core claim) ------------------------------------------

class TestTamperDetection:
    def test_altered_event_breaks_chain(self) -> None:
        log = build_log(5)
        # Tamper: replace event 2 with a different one, keep stored hashes.
        log._events[2] = dataclasses.replace(log._events[2], length=999)
        assert log.verify() is False

    def test_removed_event_breaks_chain(self) -> None:
        log = build_log(5)
        # Drop event 3 but leave its hash slot: seq/hash misalign.
        del log._events[3]
        assert log.verify() is False

    def test_inserted_event_breaks_chain(self) -> None:
        log = build_log(5)
        log._events.insert(2, ev(2))  # now two seq=2, later seqs misalign
        assert log.verify() is False

    def test_reordered_events_break_chain(self) -> None:
        log = build_log(5)
        log._events[1], log._events[3] = log._events[3], log._events[1]
        assert log.verify() is False

    def test_tampered_hash_breaks_chain(self) -> None:
        log = build_log(5)
        log._hashes[2] = "deadbeef" * 8  # forge a stored hash
        assert log.verify() is False


# --- signing + certificate verification -----------------------------------------

class TestCertificate:
    def test_seal_and_verify_roundtrip(self) -> None:
        signer = Signer.generate()
        log = build_log(6)
        cert = signer.seal(log, final_text="the document", sealed_at=2_000_000)
        result = verify_certificate(cert, signer.public_key())
        assert result.trusted is True
        assert result.reason == "certificate is valid"

    def test_document_hash_recorded(self) -> None:
        signer = Signer.generate()
        cert = signer.seal(build_log(3), final_text="hello world", sealed_at=1)
        assert cert.document_hash == sha256_hex(b"hello world")

    def test_refuses_to_seal_tampered_log(self) -> None:
        signer = Signer.generate()
        log = build_log(4)
        log._hashes[1] = "00" * 32  # break it before sealing
        with pytest.raises(ValueError, match="fails chain verification"):
            signer.seal(log, final_text="x", sealed_at=1)

    def test_wrong_key_fails_signature(self) -> None:
        signer = Signer.generate()
        other = Signer.generate()
        cert = signer.seal(build_log(3), final_text="x", sealed_at=1)
        result = verify_certificate(cert, other.public_key())
        assert result.trusted is False
        assert result.signature_ok is False
        assert result.chain_ok is True
        assert "signature" in result.reason

    def test_tampered_body_fails_signature(self) -> None:
        signer = Signer.generate()
        cert = signer.seal(build_log(3), final_text="x", sealed_at=1)
        # Forge the sealed_at after signing: signature no longer matches body.
        forged = dataclasses.replace(cert, sealed_at=cert.sealed_at + 1)
        result = verify_certificate(forged, signer.public_key())
        assert result.trusted is False
        assert result.signature_ok is False

    def test_tampered_log_in_sealed_cert_fails_chain(self) -> None:
        signer = Signer.generate()
        cert = signer.seal(build_log(5), final_text="x", sealed_at=1)
        # Tamper the log AFTER sealing.
        cert.log._events[1] = dataclasses.replace(cert.log._events[1], position=777)
        result = verify_certificate(cert, signer.public_key())
        assert result.trusted is False
        assert result.chain_ok is False

    def test_malformed_signature_hex_fails_cleanly(self) -> None:
        signer = Signer.generate()
        cert = signer.seal(build_log(2), final_text="x", sealed_at=1)
        forged = dataclasses.replace(cert, signature="not-hex-zz")
        result = verify_certificate(forged, signer.public_key())
        assert result.trusted is False
        assert result.signature_ok is False

    def test_both_failures_reported(self) -> None:
        signer = Signer.generate()
        other = Signer.generate()
        cert = signer.seal(build_log(4), final_text="x", sealed_at=1)
        cert.log._hashes[0] = "11" * 32  # break chain
        result = verify_certificate(cert, other.public_key())  # wrong key too
        assert result.ok is False
        assert result.chain_ok is False
        assert result.signature_ok is False
        assert "both" in result.reason


class TestPasteIsFirstClass:
    def test_paste_event_records_and_verifies(self) -> None:
        log = EventLog()
        log.append(ev(0, EventType.SESSION_START))
        log.append(ev(1, EventType.INSERT, text="typed"))
        log.append(ev(2, EventType.PASTE, text="a big pasted block"))
        log.append(ev(3, EventType.SESSION_END))
        assert log.verify()
        types = [e.type for e in log.events]
        assert EventType.PASTE in types


class TestSerialization:
    def test_certificate_to_dict_includes_signature(self) -> None:
        signer = Signer.generate()
        cert = signer.seal(build_log(3), final_text="x", sealed_at=42)
        d = cert.to_dict()
        assert d["signature"] == cert.signature
        assert d["sealed_at"] == 42
        assert d["log"]["head"] == cert.log.head


class TestChainOnlyFailureBranch:
    """Defense in depth: the chain check is independent of the signature. To exercise
    the 'chain broken, signature intact' branch we sign over an already-broken log's
    bytes directly, so the signature matches but the chain does not verify. This is
    the case that matters if an attacker ever held the signing key: the chain still
    catches them."""

    def test_chain_broken_signature_valid(self) -> None:
        signer = Signer.generate()
        log = build_log(4)
        log._hashes[1] = "22" * 32  # break the chain
        # Build a certificate by signing the broken log's own bytes, bypassing seal().
        body = {
            "version": 1,
            "document_hash": sha256_hex(b"x"),
            "sealed_at": 5,
            "log": log.to_dict(),
        }
        sig = signer._key.sign(canonical_bytes(body)).hex()
        cert = Certificate(
            version=1,
            document_hash=body["document_hash"],
            sealed_at=5,
            log=log,
            signature=sig,
        )
        result = verify_certificate(cert, signer.public_key())
        assert result.ok is False
        assert result.signature_ok is True   # signature matches the bytes
        assert result.chain_ok is False       # but the chain is broken
        assert "chain" in result.reason
