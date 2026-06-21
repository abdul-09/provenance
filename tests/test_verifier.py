"""
Tests for serialization round-trip and the verifier entry point. The headline: a
certificate sealed in one place, serialized to JSON, and verified somewhere else with
only the published public key, comes back valid, and any tampering with the JSON
makes it invalid.
"""
from __future__ import annotations

import json

import pytest

from provenance.recorder import SessionRecorder
from provenance.certificate import (
    Certificate,
    Signer,
    public_key_to_hex,
    public_key_from_hex,
    verify_certificate,
)
from provenance.log import EventLog, Event, EventType
from provenance.verifier import verify, Report


def record_session() -> SessionRecorder:
    r = SessionRecorder()
    r.start(1_000_000)
    r.insert(1_001_000, 0, "The quick brown fox")
    r.insert(1_002_000, 19, " jumps")
    r.paste(1_050_000, 25, " over the lazy dog")
    r.end(1_100_000)
    return r


def sealed() -> tuple[Certificate, Signer]:
    r = record_session()
    signer = Signer.generate()
    return r.seal_with(signer, sealed_at=1_200_000), signer


class TestKeySerialization:
    def test_public_key_hex_roundtrip(self) -> None:
        signer = Signer.generate()
        hexed = signer.public_key_hex()
        loaded = public_key_from_hex(hexed)
        # The loaded key verifies a cert the original signed.
        cert, _ = sealed()
        # re-sign with this signer to compare keys behaviorally
        c2 = signer.seal(record_session().log, final_text="x", sealed_at=1)
        assert verify_certificate(c2, loaded).trusted

    def test_to_hex_from_hex_identity(self) -> None:
        signer = Signer.generate()
        pk = signer.public_key()
        assert public_key_to_hex(public_key_from_hex(public_key_to_hex(pk))) == public_key_to_hex(pk)


class TestCertificateJson:
    def test_roundtrip_preserves_validity(self) -> None:
        cert, signer = sealed()
        text = cert.to_json()
        restored = Certificate.from_json(text)
        assert verify_certificate(restored, signer.public_key()).trusted

    def test_roundtrip_preserves_fields(self) -> None:
        cert, _ = sealed()
        restored = Certificate.from_json(cert.to_json())
        assert restored.version == cert.version
        assert restored.document_hash == cert.document_hash
        assert restored.sealed_at == cert.sealed_at
        assert restored.signature == cert.signature
        assert restored.log.head == cert.log.head

    def test_event_from_dict_roundtrip(self) -> None:
        e = Event(seq=0, type=EventType.PASTE, timestamp=5, position=2, length=4,
                  text_hash=Event.text_hash_of("test"))
        assert Event.from_dict(e.to_dict()) == e

    def test_log_from_dict_rebuilds_and_verifies(self) -> None:
        r = record_session()
        r.end  # already ended in record_session
        restored = EventLog.from_dict(r.log.to_dict())
        assert restored.verify()
        assert restored.head == r.log.head


class TestVerifierHappyPath:
    def test_valid_certificate(self) -> None:
        cert, signer = sealed()
        report = verify(cert.to_json(), signer.public_key_hex())
        assert report.valid is True
        assert report.chain_ok and report.signature_ok and report.document_ok
        assert report.reason == "certificate is valid"

    def test_report_facts(self) -> None:
        cert, signer = sealed()
        report = verify(cert.to_json(), signer.public_key_hex())
        # session ran 1_000_000 -> 1_100_000 ms = 100_000 ms = 100s
        assert report.duration_ms == 100_000
        assert report.event_count == 5  # start, insert, insert, paste, end
        # "The quick brown fox jumps" typed (25) + " over the lazy dog" pasted (18)
        assert report.paste_ratio == pytest.approx(18 / 43)

    def test_summary_string(self) -> None:
        cert, signer = sealed()
        report = verify(cert.to_json(), signer.public_key_hex())
        s = report.summary()
        assert "VALID" in s
        assert "100.0s" in s
        assert "pasted" in s


class TestVerifierTamperDetection:
    def test_tampered_signature_is_invalid(self) -> None:
        cert, signer = sealed()
        d = cert.to_dict()
        d["signature"] = "00" * 64
        report = verify(json.dumps(d), signer.public_key_hex())
        assert report.valid is False
        assert report.signature_ok is False

    def test_tampered_event_is_invalid(self) -> None:
        cert, signer = sealed()
        d = cert.to_dict()
        d["log"]["events"][1]["length"] = 999  # alter an event
        report = verify(json.dumps(d), signer.public_key_hex())
        assert report.valid is False
        # chain or signature (the body changed) must fail
        assert not (report.chain_ok and report.signature_ok)

    def test_wrong_key_is_invalid(self) -> None:
        cert, _ = sealed()
        other = Signer.generate()
        report = verify(cert.to_json(), other.public_key_hex())
        assert report.valid is False
        assert report.signature_ok is False

    def test_malformed_certificate_json(self) -> None:
        report = verify("{not valid json", Signer.generate().public_key_hex())
        assert report.valid is False
        assert report.reason == "certificate could not be parsed"

    def test_missing_field_certificate(self) -> None:
        report = verify(json.dumps({"version": 1}), Signer.generate().public_key_hex())
        assert report.valid is False
        assert "parsed" in report.reason

    def test_malformed_public_key(self) -> None:
        cert, _ = sealed()
        report = verify(cert.to_json(), "not-a-key")
        assert report.valid is False
        assert report.reason == "public key could not be parsed"
        assert report.event_count == 5  # cert parsed fine, key did not


class TestStructuralCheck:
    def test_impossible_edit_history_is_invalid(self) -> None:
        # Hand-build a log whose delete removes more than exists, sign it honestly,
        # so chain+signature pass but the structure is impossible.
        log = EventLog()
        log.append(Event(0, EventType.SESSION_START, 1, 0, 0, Event.text_hash_of("")))
        log.append(Event(1, EventType.INSERT, 2, 0, 3, Event.text_hash_of("abc")))
        log.append(Event(2, EventType.DELETE, 3, 0, 99, Event.text_hash_of("x" * 99)))
        signer = Signer.generate()
        cert = signer.seal(log, final_text="", sealed_at=10)
        report = verify(cert.to_json(), signer.public_key_hex())
        assert report.chain_ok is True
        assert report.signature_ok is True
        assert report.document_ok is False
        assert report.valid is False
        assert "consistent document history" in report.reason

    def test_insert_at_bad_position_is_invalid(self) -> None:
        log = EventLog()
        log.append(Event(0, EventType.SESSION_START, 1, 0, 0, Event.text_hash_of("")))
        log.append(Event(1, EventType.INSERT, 2, 5, 3, Event.text_hash_of("abc")))  # pos 5 in empty doc
        signer = Signer.generate()
        cert = signer.seal(log, final_text="", sealed_at=10)
        report = verify(cert.to_json(), signer.public_key_hex())
        assert report.document_ok is False

    def test_valid_delete_passes_structural_check(self) -> None:
        # A session with a real, in-range delete must pass document_ok (covers the
        # successful delete path in the structural replay).
        r = SessionRecorder()
        r.start(1)
        r.insert(2, 0, "hello world")
        r.delete(3, 5, 6)  # remove " world", valid
        r.end(4)
        signer = Signer.generate()
        cert = r.seal_with(signer, sealed_at=5)
        report = verify(cert.to_json(), signer.public_key_hex())
        assert report.valid is True
        assert report.document_ok is True

    def test_empty_log_duration_is_zero(self) -> None:
        # A signed certificate over an empty log: duration falls back to 0.
        signer = Signer.generate()
        cert = signer.seal(EventLog(), final_text="", sealed_at=10)
        report = verify(cert.to_json(), signer.public_key_hex())
        assert report.duration_ms == 0
        assert report.event_count == 0
