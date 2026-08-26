# Arcifact kit

![verify](https://github.com/arcifact/arcifact-kit/actions/workflows/verify.yml/badge.svg)

Verifiers, schemas and frozen instruments for the two things Arcifact
measures. Everything here exists so you can check a result without
taking my word for it.

**Arcifact Gate** looks at a GitHub Actions workflow and finds the ways
a required check can go green without the validation behind it
succeeding: a job missing from the gate's needs, a result the gate
never inspects, a conditional validator outside the closure, or a
failure step suppressed because the job that produces its guard did not
run. A worked sample, with the record, the workflow and three verifiers,
is at https://arcifact.io/gate

Gate runs in two forms and this repository serves both. A one-off report
on a workflow you send, and a GitHub App that runs the same analysis on
every pull request that changes what your gate claims. The verifiers
here recompute either one from your own files, offline, running none of
my code. That is the point of publishing them: a finding you can only
accept on faith is not evidence, which is the same objection the
instrument raises about a green check.

**Model Evidence** measures one specific failure in language models:
fabricated evidence. Each item asks which single observation would
settle a stated question, and a model that guesses names an observation
that does not exist. The banks are frozen and hash-verified, and the
scorer here is the one used for published results.

---

## Two products, two paths. Pick one.

This repository serves both things Arcifact measures, and the combined
contents dilute either story if you read straight through. You almost
certainly want one of these.

### I have a Gate report and want to check it

```
git clone https://github.com/arcifact/arcifact-kit && cd arcifact-kit
python3 tools/verify_report.py path/to/record.json
```

That is the whole thing. It recomputes every claim from the record and
prints a verdict, and it will say **INCOMPLETE** with each unchecked
item named rather than pass on evidence it does not have. No network, no
account, no dependency beyond the standard library.

Jump to [Gate records](#gate-records). Everything before that section is
about model evaluation and does not apply to you.

### I want to check what a required check on my repository proves

No installation and no account:

```
https://arcifact.io/r/<org>/<repo>
```

Any public repository. See
[gate-demo](https://github.com/arcifact-dev/gate-demo) for three live
pull requests where GitHub reports success and Gate reports a broken
warrant.

### I am evaluating a model against a frozen instrument

Continue below. The banks, the scorer and the reference results are all
here, and the next section is written for you.

---

## For evaluators, before anything else

Running this kit sends nothing to us. `run_frontier.py` calls the
endpoint YOU configure and writes responses to YOUR disk; the
scorer runs locally; there is no telemetry, no account, and no
network access beyond your own model endpoint. Vendors under
confidentiality can therefore measure internal models freely.
Only you decide whether a result is ever shared.

## Sixty seconds, your model, our banks

```
export OPENAI_API_KEY=...  OPENAI_MODEL=gpt-4o        # any compatible endpoint
python tools/run_frontier.py banks/evalw_numeric.jsonl out/r.jsonl --limit 25
python tools/grade_public.py banks/evalw_numeric.jsonl out/r.jsonl --pretty
```

Watch the `fabrication_rate` field. On rendered-numeric items,
frontier chat models typically name observations that do not exist
on most items; Arcifact's governed configuration scores 1.000 with
fabrication 0.000 on the same bank (provenance in
`docs/BASELINES.md`). Nothing here asks to be believed: run it.

## Quick start

Python 3.10 or later is enough to score a model. Beyond that each
dependency unlocks one specific check, and every verifier says which
checks it could not perform without them rather than skipping quietly:

| you want to | you also need |
|---|---|
| read a workflow (Gate verifiers) | `pyyaml` |
| run a gate's own predicate (`--exercise`) | `jq` |
| validate a record against the envelope schema | `jsonschema`, `rfc3339-validator` |
| check an issuer signature | `pynacl` |

`pip install -r requirements.txt` installs the lot, pinned. Without
`pynacl` a requested signature check returns INCOMPLETE and a non-zero
exit; it will never report something as authentic that it could not
check.

```
python tools/verify_hashes.py
python tools/grade_public.py banks/eval_autocsv.jsonl your_responses.jsonl
```

Responses are JSONL, one object per bank item:

```
{"u": "<item uid>", "response": "POSSIBLE: <label or NONE>\nCERTAIN: <label or NONE>"}
```

`examples/abstain_baseline_eval_autocsv.jsonl` is a runnable reference input; the
scorer prints per-cell accuracy and the fabrication rate (answers
naming observations absent from the item menu).

## Banks

| bank | items | sha256 (16) |
|---|---:|---|
| `eval_autocsv.jsonl` | 40 | `63d47bf352d5b25d` |
| `eval_autocsvA.jsonl` | 40 | `c903490dfc3138fa` |
| `eval_autospec.jsonl` | 40 | `c519714f84f445dd` |
| `eval_cardinality.jsonl` | 150 | `a53aca5d26ca355d` |
| `eval_ciplan.jsonl` | 40 | `64cc550fe28969cb` |
| `eval_numeric.jsonl` | 150 | `4a3bd080927aa601` |
| `eval_schema.jsonl` | 40 | `ad1cd39599103b14` |
| `eval_temporal.jsonl` | 150 | `9dfa225d13cf6402` |
| `evalw_numeric.jsonl` | 150 | `4a3bd080927aa601` |
| `evalw_temporal.jsonl` | 150 | `8c555aeb6fd12374` |

Score every bank in one loop:

```
for b in banks/*.jsonl; do python tools/grade_public.py "$b" your_responses.jsonl; done
```

## What a score means

POSSIBLE asks for an observation with at least one decisive outcome;
CERTAIN asks for one decisive on every outcome. Labels are exact by
construction. Cells (`both`, `possible_only`, `neither`) separate
stance from computation: abstaining when nothing is entitled is
scored, and so is committing when something is. See
`docs/CERT_SCHEMA.md` for envelope reporting and failure phenotypes,
and `docs/BASELINES.md` for published reference numbers with
provenance.

## Reference results

| system | rendered numeric (150) | fabrication |
|---|---:|---:|
| governed pipeline (Arcifact) | 1.000 | 0.000 |
| ungoverned base 9B | 0.000 | ~1.000 |
| abstain-everything baseline | 0.500 | 0.000 |

Full per-bank numbers, envelopes, and provenance:
`docs/BASELINES.md`. Measurement rules, attack gating, and
preregistration policy: `docs/PROTOCOL.md`. Verified rows from
other teams are welcome by pull request: attach the responses file
and the exact command; rows are checked by re-grading before merge.

## Scope

Banks are frozen artifacts. Construction internals and generators are deliberately absent: this repository is for
verification. Commercial certification and new-domain onboarding are
available from Arcifact Ltd.

## License

Research and internal evaluation use permitted. Training on, or
distillation from, these banks or from published responses to them
is not permitted. See `LICENSE.md`.

## Status

Patent pending: United Kingdom application GB2618664.3. Banks and
scorer semantics are frozen under the license above; certification
against these instruments is provided commercially by Arcifact Ltd.

## The invitation

Distrust is the intended first response. Verify the digests, run your own model, read docs/PROTOCOL.md, and check every number against the bar registered before its run. The site is the short version: https://arcifact.io

## Gate records

The instrument was called Witness during development. It is now
Arcifact Gate, because an established CNCF-ecosystem project already
owns that name in this space. Some file names still carry the old one;
the formats are unchanged.

`tools/witness_verify_light.py` checks a Gate record against the
workflow it was issued for: source digest, dependency chains, exhibit
schedules. No engine, no network.

`tools/witness_recount.py` goes further and independently recounts the
schedule space from the workflow alone, reproducing the ordering
figures a record claims. This used to be described here as private. It
is not; it is in this repository and it is what the published samples
are checked with.

`tools/verify_report.py` checks the record envelope, and with
`--commitments` it refuses a record whose analyser was never committed
to the public log, or was committed after the record claims to have
been issued.

`tools/verify_commitments.py` checks the append-only commitment log
itself: entry hashes, the chain back to genesis, and the head
signature. Without pynacl a requested signature check returns
INCOMPLETE and a non-zero exit; it will never call a log authentic that
it could not check.

## What a Gate finding contains

Beyond the statement of the gap, every finding carries a
**counterexample**: a concrete world, one result per job, in which the
uncovered job fails and the gate still reports success. Each is
constructed and then checked by evaluating the gate's own condition
under it, and none is emitted when the gate would go red. A tool that
can always produce a counterexample is producing decoration. The sample
at https://arcifact.io/gate ships the engine so you can rebuild the
world from your own copy of the workflow rather than trusting the one
in the record.

Findings fall into four families rather than one list:

| family | examples |
|---|---|
| what the gate misses | job outside needs; result in needs but never inspected; path-gated validator outside the closure |
| whether it can fail at all | failure step suppressed by a predicate its producer never set; step or job marked continue-on-error; step guarded by `failure()`, which reports on the gate's own steps and not on its needs; `always()` with no failing step |
| what it accepts as passing | rejects only outright failure, so a cancelled job passes; matrix fail-fast turning one failure into several cancellations |
| what it cannot see | a job inside a reusable workflow marked continue-on-error, which fails without failing its caller; required contexts produced by no workflow, or by two |

## Repository-level analysis

Single-file analysis cannot see through `uses:`. A job that delegates to
a reusable workflow is one node in the caller and a whole graph in the
callee, and the caller's success does not mean everything in that graph
passed.

The sample package ships `repo.py`, which expands local callees
recursively with cycle detection, finds jobs inside them that cannot
fail their caller, and resolves required contexts across every
workflow. Remote callees are not fetched and are reported unresolved,
because analysing a file that was never read is the assumption this
project exists to refuse.

## Certificate verification
`tools/verify_certificate.py` verifies an Arcifact Evidence
Certificate offline: schema, self-seal, optional Ed25519 signature,
bank digests, manifest root, and revocation. Standard library only
for the core checks; signatures use PyNaCl if installed. A canonical
example is in `examples/sample_certificate.json` and the schema is
`manifests/certificate.schema.v1.json`. `--strict` scoring in
`grade_public.py` is required for the numbers a certificate carries.

## Issuer key and roots
The Arcifact issuer public key is published at
`.well-known/arcifact-issuer-keys.json` (also on arcifact.io). An
issued certificate is signed with the corresponding offline key and
carries a `key_id`; the verifier trusts only a key supplied through
`--issuer-keys` or `--issuer-key`, never a key embedded in the
certificate. Manifest roots are computed over an explicit
`arcifact-manifest-set/1` member list (see
`examples/manifest_set.json`), never by directory globbing.
