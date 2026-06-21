# provenance

Prove a document was written, not fabricated. provenance records a writing session
as a tamper-evident, signed certificate. A skeptical reader can verify the
certificate was not altered after the fact and that it came from the service, then
watch the document grow edit by edit.

It exists because AI detectors are unreliable and honest writers get falsely
accused. A detector guesses from the text; a provenance certificate is a record of
how the text came to be. The record is evidence, not a probability.

## What the certificate claims

A writing session happened between two timestamps, produced this document, through
this sequence of edits, and the record has not changed since it was sealed. It does
not claim a human mind composed the text (someone could retype AI output), so the
product is honest about its limit: it is strong evidence of an authoring process,
which is exactly what a falsely accused writer needs.

## How the trust works

Three defenses, one per attack:

Editing the record. Every event carries the hash of the event before it, forming a
chain. Change, remove, insert, or reorder any event and the chain breaks, so a
verifier recomputing it sees the tampering.

Forging a certificate. The finished log is signed with the service Ed25519 key.
Anyone with the public key can confirm a certificate is authentic. A fabricated one
will not verify.

Knowing when it happened. The certificate records when it was sealed, so a session
that appears the night before a deadline is at least visible as such.

## Status

First commit: the trust core. The hash-chained event log and the signing and
verification of certificates, proven tamper-evident with tests. The browser capture
layer and the verification UI come in later commits, on top of this core. The
serialization is deliberately language-neutral (sorted-key JSON, UTF-8, hash the
bytes) so the future browser layer can produce byte-identical hashes.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

The test run enforces 100% line and branch coverage and fails below it.

## License

MIT
