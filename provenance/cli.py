"""
Command-line entry point.

main() takes argv and output streams as arguments rather than reaching for sys.argv
and print directly, so tests drive it in-process and capture output. The __main__
block wires the real streams.

Commands:
  keygen                       generate a keypair, print private+public hex
  verify CERT KEY              verify a certificate file against a public key file,
                               exit 0 if valid, 1 if not (scriptable)
  demo OUT                     record a sample session, seal it, write CERT and KEY
                               files so the verify command has something to check
"""
from __future__ import annotations

import argparse
import io
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .certificate import Signer, public_key_to_hex
from .recorder import SessionRecorder
from .verifier import verify as verify_certificate_json


def _cmd_keygen(stdout: io.TextIOBase) -> int:
    signer = Signer.generate()
    private_hex = signer._key.private_bytes_raw().hex()
    stdout.write(f"private: {private_hex}\n")
    stdout.write(f"public:  {signer.public_key_hex()}\n")
    return 0


def _cmd_verify(cert_path: str, key_path: str, stdout: io.TextIOBase, stderr: io.TextIOBase) -> int:
    try:
        cert_json = _read(cert_path)
        key_hex = _read(key_path).strip()
    except OSError as exc:
        stderr.write(f"error: {exc}\n")
        return 2

    report = verify_certificate_json(cert_json, key_hex)
    stdout.write(report.summary() + "\n")
    if not report.valid:
        stderr.write(f"detail: chain_ok={report.chain_ok} "
                     f"signature_ok={report.signature_ok} "
                     f"document_ok={report.document_ok}\n")
    return 0 if report.valid else 1


def _cmd_demo(out_prefix: str, stdout: io.TextIOBase) -> int:
    # A fixed sample session so the artifact is reproducible enough to demo.
    r = SessionRecorder()
    r.start(0)
    r.insert(4000, 0, "This sentence was typed by a person.")
    r.insert(9000, 36, " Then a little more was added.")
    r.paste(15000, 66, " (this part was pasted)")
    r.end(120000)

    signer = Signer.generate()
    cert = r.seal_with(signer, sealed_at=121000)

    cert_path = f"{out_prefix}.cert.json"
    key_path = f"{out_prefix}.key.hex"
    _write(cert_path, cert.to_json())
    _write(key_path, signer.public_key_hex())

    stdout.write(f"wrote {cert_path} and {key_path}\n")
    stdout.write(f"verify with: provenance verify {cert_path} {key_path}\n")
    return 0


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provenance")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keygen", help="generate a keypair")

    v = sub.add_parser("verify", help="verify a certificate against a public key")
    v.add_argument("cert", help="path to the certificate JSON file")
    v.add_argument("key", help="path to the public key hex file")

    d = sub.add_parser("demo", help="write a sample certificate and key")
    d.add_argument("out", help="output path prefix (writes OUT.cert.json, OUT.key.hex)")

    return parser


def main(argv: list[str], stdout: io.TextIOBase, stderr: io.TextIOBase) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "keygen":
        return _cmd_keygen(stdout)
    if args.command == "verify":
        return _cmd_verify(args.cert, args.key, stdout, stderr)
    # only "demo" remains; subcommands are required so nothing else reaches here
    return _cmd_demo(args.out, stdout)


def entrypoint() -> int:  # pragma: no cover
    return main(sys.argv[1:], sys.stdout, sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(entrypoint())
