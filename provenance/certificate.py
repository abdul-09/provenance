"""
The certificate layer.

A certificate is a sealed event log plus a signature over it. Sealing happens when a
writing session ends: we take the log's canonical bytes and sign them with the
service's Ed25519 private key. Anyone with the public key can verify the certificate
is authentic and unaltered.

This defends against the third attack named in the design: forging a certificate from
scratch. A fabricated certificate will not verify against the service public key. The
hash chain (in log.py) defends against editing events; the signature defends against
forging the whole thing; the sealed timestamp records when it was sealed.

Verification is intended to run server-side, somewhere the writer cannot tamper with
the verifier or substitute their own key. The public key is published; the private
key never leaves the service.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .log import EventLog, Event, EventType, canonical_bytes, sha256_hex

CERTIFICATE_VERSION = 1


def public_key_to_hex(public_key: Ed25519PublicKey) -> str:
    """Serialize an Ed25519 public key to raw hex, for publishing."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from raw hex."""
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


@dataclass(frozen=True)
class Certificate:
    """A sealed, signed writing-session record.

    version:      certificate format version
    document_hash: sha256 of the final document text (what this session produced)
    sealed_at:    server clock at seal time, ms since epoch
    log:          the hash-chained event log
    signature:    hex Ed25519 signature over the canonical certificate body
    """

    version: int
    document_hash: str
    sealed_at: int
    log: EventLog
    signature: str

    def body_dict(self) -> dict[str, Any]:
        """The signed portion. The signature itself is excluded."""
        return {
            "version": self.version,
            "document_hash": self.document_hash,
            "sealed_at": self.sealed_at,
            "log": self.log.to_dict(),
        }

    def body_bytes(self) -> bytes:
        return canonical_bytes(self.body_dict())

    def to_dict(self) -> dict[str, Any]:
        out = self.body_dict()
        out["signature"] = self.signature
        return out

    def to_json(self) -> str:
        """Serialize to a shareable JSON string. This is the artifact a writer hands
        to a verifier."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Certificate":
        return cls(
            version=data["version"],
            document_hash=data["document_hash"],
            sealed_at=data["sealed_at"],
            log=EventLog.from_dict(data["log"]),
            signature=data["signature"],
        )

    @classmethod
    def from_json(cls, text: str) -> "Certificate":
        return cls.from_dict(json.loads(text))


class Signer:
    """Holds the service private key and seals sessions into certificates."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def public_key_hex(self) -> str:
        """The public key in portable hex form, to publish for verifiers."""
        return public_key_to_hex(self._key.public_key())

    def seal(
        self, log: EventLog, final_text: str, sealed_at: int
    ) -> Certificate:
        """Seal a finished session into a signed certificate.

        Refuses to seal a log that does not verify, so a tampered log can never be
        wrapped in a valid signature.
        """
        if not log.verify():
            raise ValueError("cannot seal a log that fails chain verification")

        body = {
            "version": CERTIFICATE_VERSION,
            "document_hash": sha256_hex(final_text.encode("utf-8")),
            "sealed_at": sealed_at,
            "log": log.to_dict(),
        }
        signature = self._key.sign(canonical_bytes(body)).hex()
        return Certificate(
            version=CERTIFICATE_VERSION,
            document_hash=body["document_hash"],
            sealed_at=sealed_at,
            log=log,
            signature=signature,
        )


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a certificate. Explicit reasons, not just a bool."""

    ok: bool
    chain_ok: bool
    signature_ok: bool
    reason: str

    @property
    def trusted(self) -> bool:
        return self.ok


def verify_certificate(
    certificate: Certificate, public_key: Ed25519PublicKey
) -> VerificationResult:
    """Check a certificate against the service public key.

    Two independent checks: the hash chain must be intact, and the signature must
    match the service key. Both must pass. The result names which failed, so the
    verification UI can tell a tampered log apart from a forged signature.
    """
    chain_ok = certificate.log.verify()

    signature_ok = True
    try:
        public_key.verify(
            bytes.fromhex(certificate.signature), certificate.body_bytes()
        )
    except (InvalidSignature, ValueError):
        signature_ok = False

    if chain_ok and signature_ok:
        return VerificationResult(True, True, True, "certificate is valid")
    if not chain_ok and not signature_ok:
        return VerificationResult(False, False, False, "chain and signature both failed")
    if not chain_ok:
        return VerificationResult(False, False, True, "event chain was altered")
    return VerificationResult(False, True, False, "signature does not match service key")
