"""
Tests for the session recorder: the events must replay to the exact recorded
document, validation must reject inconsistent edits, and a sealed certificate's
document hash must match the reconstructed document.
"""
from __future__ import annotations

import pytest

from provenance.log import EventType, Event, sha256_hex
from provenance.recorder import SessionRecorder, RecorderError
from provenance.certificate import Signer, verify_certificate


def record_basic() -> SessionRecorder:
    r = SessionRecorder()
    r.start(1000)
    r.insert(1001, 0, "Hello")
    r.insert(1002, 5, " world")
    return r


class TestDocumentReconstruction:
    def test_insert_builds_document(self) -> None:
        r = record_basic()
        assert r.document == "Hello world"

    def test_insert_in_middle(self) -> None:
        r = SessionRecorder()
        r.start(1)
        r.insert(2, 0, "Helo")
        r.insert(3, 2, "l")  # "Hel" + "l" + "o" -> "Hello"
        assert r.document == "Hello"

    def test_delete_removes_text(self) -> None:
        r = record_basic()
        r.delete(1003, 5, 6)  # remove " world"
        assert r.document == "Hello"

    def test_paste_inserts_text(self) -> None:
        r = SessionRecorder()
        r.start(1)
        r.insert(2, 0, "A ")
        r.paste(3, 2, "pasted block")
        assert r.document == "A pasted block"

    def test_interleaved_edits(self) -> None:
        r = SessionRecorder()
        r.start(1)
        r.insert(2, 0, "draft")
        r.delete(3, 0, 5)
        r.insert(4, 0, "final")
        r.paste(5, 5, "!")
        assert r.document == "final!"


class TestValidation:
    def test_cannot_edit_before_start(self) -> None:
        r = SessionRecorder()
        with pytest.raises(RecorderError, match="has not started"):
            r.insert(1, 0, "x")

    def test_double_start_rejected(self) -> None:
        r = SessionRecorder()
        r.start(1)
        with pytest.raises(RecorderError, match="already started"):
            r.start(2)

    def test_cannot_edit_after_end(self) -> None:
        r = record_basic()
        r.end(2000)
        with pytest.raises(RecorderError, match="already ended"):
            r.insert(2001, 0, "x")

    def test_time_cannot_move_backward(self) -> None:
        r = SessionRecorder()
        r.start(1000)
        with pytest.raises(RecorderError, match="moved backward"):
            r.insert(999, 0, "x")

    def test_insert_out_of_range(self) -> None:
        r = SessionRecorder()
        r.start(1)
        with pytest.raises(RecorderError, match="out of range"):
            r.insert(2, 5, "x")  # doc is empty

    def test_empty_insert_rejected(self) -> None:
        r = SessionRecorder()
        r.start(1)
        with pytest.raises(RecorderError, match="non-empty"):
            r.insert(2, 0, "")

    def test_empty_paste_rejected(self) -> None:
        r = SessionRecorder()
        r.start(1)
        with pytest.raises(RecorderError, match="non-empty"):
            r.paste(2, 0, "")

    def test_paste_out_of_range(self) -> None:
        r = SessionRecorder()
        r.start(1)
        with pytest.raises(RecorderError, match="out of range"):
            r.paste(2, 3, "x")

    def test_delete_nonpositive_length(self) -> None:
        r = record_basic()
        with pytest.raises(RecorderError, match="length must be positive"):
            r.delete(1003, 0, 0)

    def test_delete_out_of_range(self) -> None:
        r = record_basic()
        with pytest.raises(RecorderError, match="out of document length"):
            r.delete(1003, 8, 10)

    def test_end_requires_open_session(self) -> None:
        r = SessionRecorder()
        with pytest.raises(RecorderError, match="has not started"):
            r.end(1)

    def test_time_check_applies_to_end(self) -> None:
        r = record_basic()
        with pytest.raises(RecorderError, match="moved backward"):
            r.end(1)  # earlier than last edit


class TestLogIntegrity:
    def test_recorded_log_verifies(self) -> None:
        r = record_basic()
        r.end(2000)
        assert r.log.verify() is True

    def test_session_markers_present(self) -> None:
        r = record_basic()
        r.end(2000)
        types = [e.type for e in r.log.events]
        assert types[0] is EventType.SESSION_START
        assert types[-1] is EventType.SESSION_END

    def test_ended_flag(self) -> None:
        r = record_basic()
        assert r.ended is False
        r.end(2000)
        assert r.ended is True


class TestPasteRatio:
    def test_all_typed_is_zero(self) -> None:
        r = record_basic()
        assert r.paste_ratio() == 0.0

    def test_all_pasted_is_one(self) -> None:
        r = SessionRecorder()
        r.start(1)
        r.paste(2, 0, "everything pasted")
        assert r.paste_ratio() == 1.0

    def test_mixed_ratio(self) -> None:
        r = SessionRecorder()
        r.start(1)
        r.insert(2, 0, "aaaa")       # 4 typed
        r.paste(3, 4, "bbbbbb")      # 6 pasted
        assert r.paste_ratio() == pytest.approx(6 / 10)

    def test_empty_session_ratio_is_zero(self) -> None:
        r = SessionRecorder()
        r.start(1)
        assert r.paste_ratio() == 0.0


class TestSealConsistency:
    """The certificate's document hash must match the reconstructed document, so the
    certificate cannot claim a document the events do not produce."""

    def test_sealed_document_hash_matches_reconstruction(self) -> None:
        r = record_basic()
        r.end(2000)
        signer = Signer.generate()
        cert = signer.seal(r.log, final_text=r.document, sealed_at=3000)
        assert cert.document_hash == sha256_hex(r.document.encode("utf-8"))
        assert verify_certificate(cert, signer.public_key()).trusted

    def test_seal_with_uses_reconstructed_document(self) -> None:
        # seal_with closes the gap: it always uses the recorder's own document, so
        # the certificate claim is consistent with the events by construction.
        r = record_basic()
        r.end(2000)
        signer = Signer.generate()
        cert = r.seal_with(signer, sealed_at=3000)
        assert cert.document_hash == sha256_hex(r.document.encode("utf-8"))
        assert verify_certificate(cert, signer.public_key()).trusted

    def test_seal_with_requires_ended_session(self) -> None:
        r = record_basic()  # not ended
        signer = Signer.generate()
        with pytest.raises(RecorderError, match="has not ended"):
            r.seal_with(signer, sealed_at=3000)
