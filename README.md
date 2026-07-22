# Local Artifact Vault

Local Artifact Vault turns a local file into a short-lived, HMAC-signed download link without uploading the file to third-party storage.

## Security model

- Files and metadata stay under an owner-only local directory.
- The signing secret is generated locally with mode `0600`.
- Links bind the artifact id, SHA-256 digest, and expiry time.
- Signature comparison uses constant-time verification.
- Downloads re-check the file digest and reject path escape or symlinks.
- Obvious credential files and token patterns are blocked before publication.
- The HTTP server binds to loopback by default.
- Publish, resolve, rejection, and cleanup events enter an owner-only local audit ledger.
- Audit records exclude signatures, source paths, source content, and client identifiers.

The content scanner is a guardrail, not a data-loss-prevention guarantee. Review every artifact before sharing it. Audit metadata helps reconstruct lifecycle decisions but never replaces the original record integrity checks.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
artifact-vault init
artifact-vault publish ./report.pdf --base-url https://files.example.invalid
artifact-vault serve
```

Put an authenticated HTTPS reverse proxy in front of the loopback server. Do not expose the server directly to the internet.

## Test

```bash
python -m unittest discover -s tests -v
```

## Non-goals

- Cloud object storage
- Permanent public hosting
- Automatic publication of model prompts, logs, databases, or configuration files
