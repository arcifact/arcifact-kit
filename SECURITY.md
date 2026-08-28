# Security and Integrity

## Reporting a vulnerability

Use GitHub private vulnerability reporting:

    https://github.com/arcifact/arcifact-kit/security/advisories/new

If that form is unavailable, email security@arcifact.io. Do not open a
public issue for a suspected vulnerability or for a suspected leak of
non-public Arcifact material.

Please include the output of `tools/verify_hashes.py`, and for scorer
issues a minimal responses file that reproduces the behaviour.

We aim to acknowledge within three working days. We will agree a
disclosure date with you rather than imposing one, and we do not
operate a bounty programme.

## Verifying a release

Every release is signed with Sigstore keyless signing. The signature
identifies the release workflow, not a key any person holds:

    cosign verify-blob \
      --bundle arcifact-kit-VERSION.tar.gz.sigstore.json \
      --certificate-identity-regexp \
        'https://github.com/arcifact/arcifact-kit/.github/workflows/release.yml@.*' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      arcifact-kit-VERSION.tar.gz

From v1.3.1 the archive is extracted and its full test suite is run
before it is signed. v1.3.0 was signed without that check and ships
incomplete bytes; use v1.3.1 or later.
