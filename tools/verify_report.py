#!/usr/bin/env python3
"""Verify an Arcifact report against the common envelope.

    python3 verify_report.py <record.json> [--sources DIR] [--profile P]
                             [--issuer-keys FILE]

The envelope (arcifact-report/1) is shared by every Arcifact instrument.
This verifier checks what is true of all of them, then dispatches to the
instrument named in the record:

  1. the envelope validates against report.schema.v1.json;
  2. the seal recomputes over the record with `sha256` removed;
  3. every source binding matches the recipient's own bytes, when
     --sources is given;
  4. the declared envelope names what was out of scope, and every
     unverified assumption says how to check it;
  5. the instrument payload validates against its own profile;
  6. for the issued profile only: an out of band issuer signature, an
     expiry that has not passed, and a revocation pointer.

Verdicts, deliberately distinct:

  VALID                  issued profile, every check passed, signature
                         verified against a key supplied out of band.
  SELF_CONSISTENT_REPORT the record is internally consistent and bound
                         to the sources given, but is not an issued
                         certificate. This is NOT an authenticity claim.
  INCOMPLETE             nothing contradicts the record, but a check
                         could not be performed here. Says which.
  INVALID                a check failed. Says which.

A verifier that always returns VALID is worthless, so this one is built
to fail: run it against a record whose payload has been edited, or
against a different source file, and it will say so.

Requires Python 3.9+. Uses jsonschema when available for full schema
validation, and falls back to structural checks with an INCOMPLETE note
when it is absent. pynacl is required only for issued signatures.
"""
import re
import subprocess
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
# The schema sits beside the verifier in a disclosure package and in
# ../manifests in the kit. Looking in only one place made the advertised
# command return INCOMPLETE and exit 1 in every package shipped.
_CANDIDATES = (os.path.join(HERE, "report.schema.v1.json"),
               os.path.join(HERE, "..", "manifests", "report.schema.v1.json"),
               os.path.join(HERE, "manifests", "report.schema.v1.json"))
SCHEMA = next((p for p in _CANDIDATES if os.path.exists(p)), _CANDIDATES[0])

PROFILE_RANK = {"draft": 0, "report": 1, "issued": 2}


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


class Result:
    def __init__(self):
        self.failures = []
        self.incompletes = []
        self.notes = []

    def fail(self, msg):
        self.failures.append(msg)

    def incomplete(self, msg):
        self.incompletes.append(msg)

    def note(self, msg):
        self.notes.append(msg)


def check_envelope(rec, res):
    if rec.get("schema") != "arcifact-report/1":
        res.fail(f"schema must be arcifact-report/1, got "
                 f"{rec.get('schema')!r}")
        return
    if not os.path.exists(SCHEMA):
        # a schema we cannot read is a check we could not perform, not a
        # check that failed. Saying INVALID here would punish every
        # recipient who unpacks the record on its own.
        res.incomplete("envelope schema not found beside the verifier: "
                       "structure checked, schema conformance not. Fetch "
                       "https://arcifact.io/manifests/report.schema.v1.json "
                       "to complete this check")
        for k in ("instrument", "instrument_version", "profile", "subject",
                  "source_bindings", "claims", "envelope", "assumptions",
                  "provenance", "issued", "payload", "sha256"):
            if k not in rec:
                res.fail(f"required envelope field missing: {k}")
        return
    try:
        import jsonschema
        from jsonschema import FormatChecker
        schema = json.load(open(SCHEMA))
        jsonschema.validate(rec, schema,
                            format_checker=FormatChecker())
        res.note("envelope schema: validated with jsonschema")
    except ImportError:
        res.incomplete("jsonschema not installed: envelope validated "
                       "structurally only (pip install jsonschema)")
        for k in ("instrument", "instrument_version", "profile",
                  "subject", "source_bindings", "claims", "envelope",
                  "assumptions", "provenance", "issued", "payload",
                  "sha256"):
            if k not in rec:
                res.fail(f"required envelope field missing: {k}")
    except Exception as exc:
        res.fail(f"envelope schema validation failed: "
                 f"{str(exc).splitlines()[0][:160]}")


def check_seal(rec, res):
    claimed = rec.get("sha256")
    if not claimed:
        res.fail("no seal present")
        return
    body = {k: v for k, v in rec.items() if k != "sha256"}
    if hashlib.sha256(_canon(body)).hexdigest() != claimed:
        res.fail("seal does not recompute: the record has been altered "
                 "since it was sealed")


def check_sources(rec, res, sources_dir):
    bindings = rec.get("source_bindings") or []
    if not sources_dir:
        res.incomplete(f"{len(bindings)} source binding(s) not checked: "
                       "pass --sources DIR with your own copies")
        return
    for b in bindings:
        name = os.path.basename(b.get("path", ""))
        cand = os.path.join(sources_dir, name)
        if not os.path.exists(cand):
            res.incomplete(f"source not found locally: {name}")
            continue
        got = _sha256_file(cand)
        if got != b.get("sha256"):
            res.fail(f"source mismatch for {name}: record binds "
                     f"{b.get('sha256','')[:16]}..., your copy is "
                     f"{got[:16]}...")
        else:
            res.note(f"source binding verified: {name}")


def check_honesty(rec, res):
    """The envelope must state its own limits. These are the checks that
    stop a record quietly widening its own scope."""
    env = rec.get("envelope") or {}
    if not (env.get("out_of_scope") or []):
        res.fail("envelope declares nothing out of scope: every result "
                 "has a boundary and must name it")
    for a in rec.get("assumptions") or []:
        if a.get("verified") is False and not a.get("how_to_verify"):
            res.fail(f"unverified assumption gives no way to check it: "
                     f"{str(a.get('statement'))[:70]}")
    for c in rec.get("claims") or []:
        if c.get("verdict") == "unresolved" and not c.get("settled_by"):
            res.fail(f"unresolved claim does not name what would settle "
                     f"it: {str(c.get('id'))[:40]}")


def check_gate_payload(rec, res):
    p = rec.get("payload") or {}
    if p.get("payload_schema") != "gate-ci/1":
        res.fail("payload_schema must be gate-ci/1 for instrument gate")
        return
    gate = p.get("gate") or {}
    enf = gate.get("enforcement")
    if enf == "unverified":
        res.note("gate enforcement unverified: the record does not "
                 "claim this gate is required, which a workflow file "
                 "cannot establish")
    elif enf == "not_enforced":
        res.note("gate is confirmed NOT enforced: structurally open but "
                 "with no merge consequence")
    covered = set(p.get("covered_jobs") or [])
    for u in p.get("uncovered_jobs") or []:
        if u.get("job") in covered:
            res.fail(f"job {u.get('job')!r} is listed as both covered "
                     f"and uncovered")
    counts = p.get("ordering_counts") or {}
    if counts:
        try:
            total = int(counts.get("total", 0))
            first = int(counts.get("gate_first", 0))
            after = int(counts.get("after_fix", -1))
            if not (0 <= first <= total):
                res.fail("ordering counts incoherent: gate_first is not "
                         "within total")
            if after > total:
                res.fail("ordering counts incoherent: after_fix exceeds "
                         "total")
        except (TypeError, ValueError):
            res.fail("ordering counts are not integers")


def check_model_payload(rec, res):
    p = rec.get("payload") or {}
    if p.get("payload_schema") != "model-evidence/1":
        res.fail("payload_schema must be model-evidence/1 for "
                 "instrument model-evidence")
        return
    fr = p.get("fabrication_rate")
    if isinstance(fr, (int, float)) and not (0.0 <= fr <= 1.0):
        res.fail(f"fabrication_rate out of range: {fr}")
    if p.get("scorer_strict") is False:
        res.note("scorer_strict is false: scores are not comparable "
                 "with strictly scored runs")
    for b in p.get("banks") or []:
        if not isinstance(b.get("n"), int) or b["n"] < 1:
            res.fail(f"bank {b.get('name')!r} has no positive item count")


def check_issued(rec, res, issuer_keys):
    prof = rec.get("profile")
    if prof != "issued":
        return
    sig = rec.get("signature") or {}
    if not sig.get("sig"):
        res.fail("issued profile requires a signature")
        return
    if not issuer_keys:
        res.incomplete("issued signature not verified: pass "
                       "--issuer-keys with a key obtained out of band. "
                       "A key carried inside the record proves nothing")
        return
    try:
        from nacl.signing import VerifyKey
    except ImportError:
        res.incomplete("pynacl not installed: signature not verified")
        return
    try:
        keys = json.load(open(issuer_keys))
        table = {k["key_id"]: k["public_key"]
                 for k in keys.get("keys", [])}
        pub = table.get(sig.get("key_id"))
        if not pub:
            res.fail(f"no published key for key_id "
                     f"{sig.get('key_id')!r}")
            return
        body = {k: v for k, v in rec.items()
                if k not in ("sha256", "signature")}
        VerifyKey(bytes.fromhex(pub)).verify(
            _canon(body), bytes.fromhex(sig["sig"]))
        res.note(f"issuer signature verified against key "
                 f"{sig.get('key_id')}")
    except Exception as exc:
        res.fail(f"signature verification failed: {str(exc)[:100]}")
    exp = _parse_dt(rec.get("expires"))
    if exp and exp < datetime.now(timezone.utc):
        res.fail(f"record expired on {rec.get('expires')}")
    if not rec.get("revocation"):
        res.fail("issued profile requires a revocation pointer")



FEATURE_COMPONENTS = {"counterexamples": "counterexample.py",
                      "sensitivity": "sensitivity.py",
                      "repository_level": "repo.py"}


def check_feature_bindings(rec, res):
    """A record that carries evidence from a component must name that
    component's digest. Otherwise it asserts newer evidence under an
    older instrument, which is the one thing the commitment log exists
    to prevent, and which a shipped record did."""
    # the build manifest now keys modules by path, so match on basename:
    # counterexample.py may appear as witness/counterexample.py
    raw = set((rec.get("provenance") or {}).get("tool_digests") or {})
    tools = raw | {k.rsplit("/", 1)[-1] for k in raw}
    payload = rec.get("payload") or {}
    env = rec.get("envelope") or {}
    for key, comp in FEATURE_COMPONENTS.items():
        present = bool(payload.get(key) or env.get(key))
        if present and comp not in tools:
            res.fail(f"record carries {key!r} but does not bind {comp}: "
                     f"the evidence post-dates the instrument it names")


def check_anchor(rec, res):
    """Check the record's chronology anchor.

    The anchor is a pair of RFC 3161 timestamp tokens over the
    commitment log's signed head, from two independent authorities. The
    head is the terminus of a hash chain over every entry, so a head
    that existed at a moment could only have come from a log that
    existed then.

    Nothing here involves an Arcifact key: the signatures are the
    authorities' own, which is what makes them worth having. This
    function checks the token's embedded time against the record's
    issuance and confirms the imprint commits to the head. Full
    signature verification is a one-line openssl call, run here when
    openssl is available and reported as not performed when it is not,
    never assumed."""
    import subprocess
    a = (rec.get("provenance") or {}).get("anchor")
    if not a:
        res.incomplete("record names no anchor: its commitment timestamps "
                       "are issuer-stated only")
        return
    issued = _parse_dt(rec.get("issued"))
    head = a.get("head")
    declared = (rec.get("provenance") or {}).get("commitment_log_head")
    if head and declared and head != declared:
        res.fail(f"the anchor is over head {str(head)[:16]} but the record "
                 f"declares {str(declared)[:16]}")

    # Anchor files sit beside the record in a single-record package and
    # at the package root when records are nested (uv/, ruff/). Look in
    # both rather than reporting a present file as missing.
    d1 = os.path.dirname(os.path.abspath(rec_path_hint[0] or "."))
    cands = [d1, os.path.dirname(d1)]

    def _find(name):
        for c in cands:
            p = os.path.join(c, name)
            if os.path.exists(p):
                return p
        return os.path.join(d1, name)

    headfile = _find("commitment-head.txt")
    here = os.path.dirname(headfile)
    if os.path.exists(headfile):
        onfile = open(headfile).read().strip()
        if head and onfile != head:
            res.fail("commitment-head.txt does not contain the head the "
                     "anchor claims to cover")
    tokens = a.get("tokens") or []
    if len(tokens) < 2:
        res.incomplete(f"{len(tokens)} timestamp authority(ies) present; two "
                       f"independent ones are expected")
    for tk in tokens:
        f = _find(tk.get("file", ""))
        if not os.path.exists(f):
            res.incomplete(f"{tk.get('file')} not beside this record: its "
                           f"signature and time were not checked")
            continue

        # The authoritative time is the one INSIDE the signed token, not
        # the one the record declares beside it. An earlier version
        # trusted the JSON field, so editing that field and resealing
        # was enough to fake the ordering.
        embedded = None
        try:
            rep = subprocess.run(["openssl", "ts", "-reply", "-in", f,
                                  "-text"], capture_output=True, text=True,
                                 timeout=30)
            m = re.search(r"Time stamp:\s*(.+)", rep.stdout)
            if m:
                embedded = _parse_ts(m.group(1).strip())
        except FileNotFoundError:
            res.incomplete(f"openssl not available: {tk.get('authority')} "
                           f"token time could not be read from the token, "
                           f"so the ordering was NOT checked")
            continue
        except Exception as exc:
            res.incomplete(f"{tk.get('authority')} token could not be read "
                           f"({str(exc)[:40]}): ordering NOT checked")
            continue
        if not embedded:
            res.fail(f"{tk.get('authority')} token carries no readable time")
            continue

        declared = _parse_ts(tk.get("timestamp"))
        if declared and declared != embedded:
            res.fail(f"{tk.get('authority')}: the record declares "
                     f"{tk.get('timestamp')} but the signed token says "
                     f"{embedded.strftime('%b %d %H:%M:%S %Y')} GMT")
        if issued and embedded >= issued:
            res.fail(f"{tk.get('authority')} signed the head at "
                     f"{embedded.strftime('%b %d %H:%M:%S %Y')} GMT, which "
                     f"is NOT before issuance {rec.get('issued')}")
        else:
            res.note(f"{tk.get('authority')} signed the head at "
                     f"{embedded.strftime('%b %d %H:%M:%S %Y')} GMT "
                     f"(read from the token), before issuance "
                     f"{rec.get('issued')}")
        args = ["openssl", "ts", "-verify", "-data", headfile, "-in", f]
        if "digicert" in str(tk.get("file", "")).lower():
            args += ["-CApath", "/etc/ssl/certs"]
        else:
            args += ["-CAfile", _find("freetsa-cacert.pem"),
                     "-untrusted", _find("freetsa-tsa.crt")]
        try:
            out = subprocess.run(args, capture_output=True, text=True,
                                 timeout=30)
            blob = out.stdout + out.stderr
            if "Verification: OK" in blob:
                res.note(f"{tk.get('authority')} token signature VERIFIED "
                         f"against its certificate chain")
            else:
                res.fail(f"{tk.get('authority')} token did not verify: "
                         f"{blob.strip().splitlines()[-1][:80] if blob.strip() else 'no output'}")
        except FileNotFoundError:
            res.incomplete(f"openssl not available: {tk.get('authority')} "
                           f"signature not checked. Run: openssl ts -verify "
                           f"-data commitment-head.txt -in {tk.get('file')} "
                           f"-CApath /etc/ssl/certs")
        except Exception as exc:
            res.incomplete(f"{tk.get('authority')} signature check could not "
                           f"run ({str(exc)[:50]})")


def _parse_ts(s):
    """RFC 3161 tokens print times as 'Aug 17 20:01:15 2026 GMT'."""
    import datetime
    if not s:
        return None
    try:
        # tokens print GMT; make it explicit so it compares against the
        # record's timezone-aware issuance rather than raising
        naive = datetime.datetime.strptime(
            str(s).replace(" GMT", "").strip(), "%b %d %H:%M:%S %Y")
        return naive.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None


def check_analyser_commitment(rec, res, commitments_path):
    """Was the instrument that produced this record committed BEFORE the
    record was issued?

    A result is only as good as the instrument behind it. An instrument
    that can be edited between the bar being set and the result being
    published is not an instrument, it is an opinion with a hash. So the
    analyser's exact bytes are committed to the public append-only log,
    and this check refuses a record whose analyser was never committed,
    or was committed only after the record claims to have been issued.

    The rule binds the issuer: they cannot alter what the analyser
    concludes and reissue under the old reputation, because the digest
    would not match any prior entry."""
    tools = ((rec.get("provenance") or {}).get("tool_digests")
             or (rec.get("payload") or {}).get("analyser") or {})
    if not tools:
        res.incomplete("record carries no analyser digests: the "
                       "instrument behind it cannot be checked")
        return
    if not commitments_path:
        res.incomplete(f"{len(tools)} analyser digest(s) not checked: "
                       "pass --commitments with the published log")
        return
    try:
        log = json.load(open(commitments_path))
    except Exception as exc:
        res.fail(f"cannot read commitment log: {str(exc)[:60]}")
        return
    entries = log.get("entries") or []

    # Validate the log before believing anything in it. A corrupted final
    # entry previously left verify_commitments.py returning INVALID while
    # this verifier happily reported the analysers as committed.
    prev, broken = "0" * 64, None
    for i, e in enumerate(entries, 1):
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        if hashlib.sha256(json.dumps(body, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest() != e.get("entry_hash"):
            broken = f"entry {i}: hash does not recompute"
            break
        if e.get("prev") != prev:
            broken = f"entry {i}: broken chain"
            break
        prev = e.get("entry_hash")
    sig_head = (log.get("signature") or {}).get("head")
    if broken:
        res.fail(f"the supplied commitment log is invalid ({broken}): no "
                 f"claim about what was committed can rest on it")
        return
    if sig_head and prev != sig_head:
        res.fail("the supplied commitment log does not end at its own "
                 "signed head: no commitment claim can rest on it")
        return

    declared = (rec.get("provenance") or {}).get("commitment_log_head")
    actual = (log.get("signature") or {}).get("head")
    if declared and actual and declared != actual:
        res.fail(f"record declares commitment head {declared[:16]} but the "
                 f"supplied log's head is {actual[:16]}: the record was not "
                 f"issued against this log")
    by_digest = {}
    for e in entries:
        if e.get("digest"):
            by_digest.setdefault(e["digest"], e)
    issued = _parse_dt(rec.get("issued"))
    for name, dig in tools.items():
        e = by_digest.get(dig)
        if not e:
            res.fail(f"analyser {name} (digest {dig[:12]}) was never "
                     f"committed to the log: this record cannot be "
                     f"relied on as an issued result")
            continue
        ts = _parse_dt(e.get("utc"))
        if issued and ts and ts > issued:
            res.fail(f"analyser {name} was committed AFTER the record "
                     f"was issued ({e.get('utc')} > {rec.get('issued')})")
        else:
            res.note(f"analyser {name} committed at entry "
                     f"{e.get('n')} on {e.get('utc')}")


DISPATCH = {"gate": check_gate_payload,
            "model-evidence": check_model_payload}


rec_path_hint = [None]


def verify(path, sources_dir=None, want_profile=None, issuer_keys=None,
           commitments=None):
    rec_path_hint[0] = path
    res = Result()
    try:
        rec = json.load(open(path))
    except Exception as exc:
        print(f"VERDICT  INVALID\n  cannot parse {path}: {exc}")
        return 1
    if not isinstance(rec, dict):
        print("VERDICT  INVALID\n  record is not an object")
        return 1

    check_envelope(rec, res)
    check_seal(rec, res)
    check_sources(rec, res, sources_dir)
    check_honesty(rec, res)

    instrument = rec.get("instrument")
    handler = DISPATCH.get(instrument)
    if handler is None:
        res.incomplete(f"unknown instrument {instrument!r}: envelope "
                       f"checked, payload not interpreted by this "
                       f"verifier version")
    else:
        handler(rec, res)

    check_issued(rec, res, issuer_keys)
    check_feature_bindings(rec, res)
    check_anchor(rec, res)
    check_analyser_commitment(rec, res, commitments)

    profile = rec.get("profile", "draft")
    if want_profile:
        # a requested profile is a FLOOR, never a downgrade
        if PROFILE_RANK.get(profile, 0) < PROFILE_RANK.get(want_profile, 0):
            res.fail(f"record profile {profile!r} is weaker than the "
                     f"required {want_profile!r}")

    print(f"record              {os.path.basename(path)}")
    print(f"instrument          {instrument} "
          f"{rec.get('instrument_version','')}")
    print(f"profile             {profile}")
    subj = rec.get("subject") or {}
    print(f"subject             {subj.get('kind','?')} "
          f"{subj.get('name','?')}")
    claims = rec.get("claims") or []
    tally = {}
    for c in claims:
        tally[c.get("verdict")] = tally.get(c.get("verdict"), 0) + 1
    print(f"claims              {len(claims)}  {tally}")
    for n in res.notes:
        print(f"  note              {n}")
    for i in res.incompletes:
        print(f"  not checked       {i}")
    for f in res.failures:
        print(f"  FAILED            {f}")

    if res.failures:
        verdict = "INVALID"
    elif profile == "issued" and not res.incompletes:
        verdict = "VALID"
    elif res.incompletes:
        verdict = "INCOMPLETE"
    else:
        verdict = "SELF_CONSISTENT_REPORT"
    print(f"VERDICT             {verdict}")
    if verdict == "SELF_CONSISTENT_REPORT":
        print("                    (self consistency and source "
              "binding, NOT authenticity or issuance)")
    return 0 if verdict in ("VALID", "SELF_CONSISTENT_REPORT") else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("record")
    ap.add_argument("--sources", help="directory holding your own "
                                      "copies of the bound sources")
    ap.add_argument("--profile", choices=["draft", "report", "issued"],
                    help="minimum profile you require")
    ap.add_argument("--issuer-keys", help="published issuer key file, "
                                          "obtained out of band")
    ap.add_argument("--commitments", help="the published append-only "
                    "commitment log, to check that the analyser behind "
                    "this record was committed before it was issued")
    a = ap.parse_args()
    return verify(a.record, a.sources, a.profile, a.issuer_keys,
                  a.commitments)


if __name__ == "__main__":
    sys.exit(main())
