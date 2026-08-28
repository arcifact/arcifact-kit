# Changelog

## v1.3.1

Fixes the release archive. v1.3.0 was signed correctly and shipped
incomplete bytes.

The workflow built the tarball from an allowlist of paths that omitted
`examples/`, `SECURITY.md`, `CHANGELOG.md` and the manifests the test
suite reads. It tested the source tree and then signed a different
archive, so extracting v1.3.0 and running its own suite produced 39
passed and 25 failed. The signature was genuine; it attested to bytes
that do not work.

The archive now ships everything except what a recipient must not
receive, with sorted entries and normalised ownership and timestamps so
it is reproducible. A new step extracts the built archive into a clean
directory and runs the full suite against it before the signing step.

Release actions are pinned by commit SHA rather than mutable major
tags, and a dispatched build now refuses a tag that does not exist or
does not point at the commit being built.

No library or bank content changed between v1.3.0 and v1.3.1.

## v1.3.0

Adds Sigstore keyless signing to the release, so a downloaded archive
can be verified against the workflow identity that produced it without
trusting a key we hold.

## v1.2.1

Fixes the public verification workflow, which had been red since v1.2.0.

v1.2.0 tightened the issued profile to require a checked revocation
state and verified manifest members. The CI step that asserts the
sample certificate verifies VALID end to end was not updated to supply
`--revocation` or `--manifest-dir`, so it returned INCOMPLETE and the
assertion failed. The verifier was correct throughout; the invocation
was not.

v1.2.0 is superseded. Nothing about the certificate format, the
verifier semantics or any published result changes.

A note on why this mattered more than an ordinary CI break: Arcifact
sells assurance that a green check means what it claims, while its own
public verification badge was red. That is the failure this project
exists to detect, and it went unnoticed for a week.

## 1.1.0 - 2026-08-15
Hardened the verification boundary in response to external adversarial
review. Certificate schema compatibility: v1 (arcifact-certificate/1).

### Security
- Certificate verifier now returns a verdict MATRIX, not a single
  GREEN flag. VALID requires every mandatory check for the profile;
  anything unavailable is INCOMPLETE/UNKNOWN, never VALID.
- The published closed JSON Schema is now ENFORCED (jsonschema when
  available; a bounded builtin check otherwise).
- Issuer authenticity: signatures verify against an out-of-band
  Arcifact key by key_id. A key embedded in a certificate is never
  trusted alone. Absent/unverifiable signatures fail closed for the
  issued profile; signature stripping is caught.
- Manifest roots use an explicit arcifact-manifest-set/1 member list;
  directory globbing removed.
- Witness rejects empty artifact lists, unknown artifact types, and
  workflows whose needs reference nonexistent jobs.
- Full SHA-256 comparison restored in bank integrity (display prefix
  kept separately).

### Tests and CI
- 23 real adversarial tests with committed public fixtures; no no-ops.
  Signature tests skip explicitly without pynacl. CI fails if fixtures
  are missing. Actions pinned by commit SHA.

### Docs
- Canonical schema at manifests/certificate.schema.v1.json (site and
  kit share the bytes). Threat model added. Issuer key and root policy
  documented. "source-available" replaces "open".

### Deprecates
- 1.0.0 (pre-hardening). Use 1.1.0 for any verification.

## 1.2.0 - 2026-08-15
Full chain coherence in response to the third external review.

### Security
- Issued profile now requires manifest-set AND revocation checks for
  VALID (previously VALID without them).
- Profile is a floor, never a downgrade: an issued certificate cannot
  be re-verified as a report. VALID is reserved for issued; reports
  return SELF_CONSISTENT_REPORT.
- JSON Schema format checking enabled; datetimes validated engine-
  independently (a "banana" date can never pass).
- Cross-field semantics enforced: per-bank coverage 1.0, stance totals
  equal bank totals, aggregate fabrication consistent, strict scorer
  provenance, issue time not in the future, unique bank names.
- Manifest-set now verifies member file bytes, not just the index root.
- Revocation record signed and freshness-checked (arcifact-revocation/2);
  unsigned or stale revocation is not "checked_not_revoked".
- Verifier is crash-proof on hostile input.

### New
- witness_recount.py: exact recount verifier reproduces N, ordering
  shares (integer numerator/denominator) and what-if counts.
- Light verifier reports explicit dimensions and returns
  CONSISTENT_LIGHT; it no longer implies numeric claims were checked.

### Scorer
- Structured JSON errors with line numbers; repeated-key and missing-
  field responses are malformed (fatal under strict); exact score
  numerators/denominators and observation counts emitted.

### Deprecates
- 1.0.0 and 1.1.0 for issued-certificate verification.
