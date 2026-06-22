"""Tests for the CLI, driven in-process with a string buffer and tmp files."""
from __future__ import annotations

import io

import pytest

from provenance.cli import main, build_parser


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, out, err)
    return code, out.getvalue(), err.getvalue()


class TestKeygen:
    def test_prints_private_and_public(self) -> None:
        code, out, _ = run(["keygen"])
        assert code == 0
        assert "private:" in out
        assert "public:" in out
        # public key is 32 bytes -> 64 hex chars
        public_line = [l for l in out.splitlines() if l.startswith("public:")][0]
        assert len(public_line.split()[1]) == 64


class TestDemoAndVerify:
    def test_demo_writes_files(self, tmp_path) -> None:
        prefix = str(tmp_path / "sample")
        code, out, _ = run(["demo", prefix])
        assert code == 0
        assert (tmp_path / "sample.cert.json").exists()
        assert (tmp_path / "sample.key.hex").exists()
        assert "verify with:" in out

    def test_demo_then_verify_is_valid(self, tmp_path) -> None:
        prefix = str(tmp_path / "sample")
        run(["demo", prefix])
        code, out, err = run([
            "verify",
            f"{prefix}.cert.json",
            f"{prefix}.key.hex",
        ])
        assert code == 0
        assert "VALID" in out
        assert err == ""

    def test_verify_reports_facts(self, tmp_path) -> None:
        prefix = str(tmp_path / "sample")
        run(["demo", prefix])
        _, out, _ = run(["verify", f"{prefix}.cert.json", f"{prefix}.key.hex"])
        assert "events over" in out
        assert "pasted" in out


class TestVerifyFailures:
    def test_wrong_key_exits_nonzero(self, tmp_path) -> None:
        prefix = str(tmp_path / "sample")
        run(["demo", prefix])
        # overwrite the key with a different valid public key
        _, kout, _ = run(["keygen"])
        other_pub = [l for l in kout.splitlines() if l.startswith("public:")][0].split()[1]
        (tmp_path / "sample.key.hex").write_text(other_pub)

        code, out, err = run(["verify", f"{prefix}.cert.json", f"{prefix}.key.hex"])
        assert code == 1
        assert "INVALID" in out
        assert "signature_ok=False" in err

    def test_tampered_cert_exits_nonzero(self, tmp_path) -> None:
        prefix = str(tmp_path / "sample")
        run(["demo", prefix])
        cert_file = tmp_path / "sample.cert.json"
        # The JSON stores hashes, not text, so tamper a structural number: bump the
        # sealed_at, which is part of the signed body and will break the signature.
        import json
        data = json.loads(cert_file.read_text())
        data["sealed_at"] = data["sealed_at"] + 1
        cert_file.write_text(json.dumps(data))
        code, out, _ = run(["verify", f"{prefix}.cert.json", f"{prefix}.key.hex"])
        assert code == 1
        assert "INVALID" in out

    def test_missing_cert_file_errors(self, tmp_path) -> None:
        code, _, err = run(["verify", str(tmp_path / "nope.json"), str(tmp_path / "nope.hex")])
        assert code == 2
        assert "error:" in err

    def test_malformed_cert_is_invalid(self, tmp_path) -> None:
        cert = tmp_path / "bad.json"
        cert.write_text("{not json")
        key = tmp_path / "k.hex"
        key.write_text("00" * 32)
        code, out, _ = run(["verify", str(cert), str(key)])
        assert code == 1
        assert "INVALID" in out


class TestParser:
    def test_requires_subcommand(self) -> None:
        with pytest.raises(SystemExit) as exc:
            run([])
        assert exc.value.code == 2

    def test_unknown_subcommand(self) -> None:
        with pytest.raises(SystemExit) as exc:
            run(["bogus"])
        assert exc.value.code == 2

    def test_parser_builds_verify(self) -> None:
        args = build_parser().parse_args(["verify", "c.json", "k.hex"])
        assert args.command == "verify"
        assert args.cert == "c.json"
        assert args.key == "k.hex"
