#!/usr/bin/env python3
"""Verify an Arcifact Evidence Certificate offline.

Verdicts:
  VALID                   issued profile only: every mandatory
                          dimension checked and passed, including
                          manifest-set and revocation;
  SELF_CONSISTENT_REPORT  report/draft profile: schema + seal +
                          expiry pass; no issuance claim is made;
  INCOMPLETE              nothing failed, but a mandatory check for
                          the effective profile could not run;
  INVALID                 any dimension failed.

Profile is a FLOOR, never a downgrade: the effective profile is the
stronger of the certificate's own profile and --profile. An issued
certificate can never be re-verified as a mere report.

Canonicalization is arcifact-canon/1: JSON with sorted keys and
compact separators, UTF-8. (This is deliberately NOT described as
RFC 8785; number and Unicode edge cases are constrained by the
schema instead.)

Issued-profile requirements (all mandatory):
  schema pass under the full jsonschema engine with format checking;
  seal pass; issuer signature pass against an OUT-OF-BAND anchor;
  banks pass (full SHA-256); manifest-set pass, including member file
  bytes when --manifest-dir is given; revocation checked against a
  SIGNED, FRESH revocation record and not revoked; expiry current;
  cross-field semantics pass (coverage 1.0 per bank, stance totals
  equal bank totals, aggregate fabrication consistent with per-bank
  values, unique bank names, issue time not in the future, strict
  scorer provenance).

The bars/thresholds OUTCOME is reported separately from validity:
a perfectly authentic certificate can record a failed evaluation.

Usage:
  python3 verify_certificate.py CERT.json
      [--schema certificate.schema.v1.json]
      [--issuer-keys issuer_keys.json | --issuer-key HEX]
      [--banks DIR] [--manifest-set INDEX.json] [--manifest-dir DIR]
      [--revocation revocation.json] [--profile issued|report|draft]
      [--pretty]
Patents pending GB2618664.3, GB2619009.0."""
import argparse
import datetime
import hashlib
import hmac
import json
import pathlib
import re
import sys

SCHEMA_ID = "arcifact-certificate/1"
SCHEMA_IDS = ("arcifact-certificate/1", "arcifact-certificate/2")
CANON_ID = "arcifact-canon/1"
RANK = {"draft": 0, "report": 1, "issued": 2}


def sha_hex(b):
    return hashlib.sha256(b).hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sealed_payload(cert):
    body = {k: v for k, v in cert.items()
            if k not in ("sha256", "signature")}
    return canon(body)


def signed_payload(cert):
    body = {k: v for k, v in cert.items() if k != "signature"}
    return canon(body)


def parse_dt(v):
    return datetime.datetime.fromisoformat(
        str(v).replace("Z", "+00:00"))


# ---------- schema ----------
def check_schema(cert, schema_path):
    if schema_path and schema_path.is_file():
        try:
            import jsonschema
            schema = json.loads(schema_path.read_text())
            v = jsonschema.Draft202012Validator(
                schema, format_checker=jsonschema.FormatChecker())
            errs = sorted(v.iter_errors(cert), key=lambda e: e.path)
            return ("pass" if not errs else "fail",
                    [f"{'/'.join(map(str, e.path))}: {e.message}"
                     for e in errs[:12]], "jsonschema")
        except ImportError:
            pass
    errs = []
    if cert.get("schema_version") not in SCHEMA_IDS:
        errs.append("schema_version must be one of " + ", ".join(SCHEMA_IDS))
    if not re.fullmatch(r"[0-9a-f]{64}", str(cert.get("sha256", ""))):
        errs.append("sha256 not a full sha256")
    for k in ("issued", "expires"):
        try:
            parse_dt(cert.get(k))
        except Exception:
            errs.append(f"{k} not a parseable ISO-8601 datetime")
    if not isinstance(cert.get("banks"), list) or not cert.get("banks"):
        errs.append("banks must be a non-empty array")
    return ("pass" if not errs else "fail", errs, "builtin")


# ---------- cross-field semantics ----------
def check_semantics(cert, effective):
    try:
        return _check_semantics(cert, effective)
    except Exception as e:
        return ("fail", [f"semantics check aborted: {e}"])


def _check_semantics(cert, effective):
    errs = []
    banks = cert.get("banks", []) or []
    names = [b.get("bank") for b in banks if isinstance(b, dict)]
    if len(names) != len(set(names)):
        errs.append("duplicate bank names")
    total_n = 0
    rates = []
    for b in banks:
        if not isinstance(b, dict):
            errs.append("bank entry is not an object")
            continue
        try:
            total_n += int(b.get("n", 0) or 0)
        except (TypeError, ValueError):
            errs.append("bank n is not an integer")
        rates.append(float(b.get("fabrication_rate", 0) or 0))
        if effective == "issued" and b.get("coverage") != 1.0:
            errs.append(f"bank {b.get('bank')}: issued requires "
                        f"coverage 1.0")
    st = cert.get("stance", {})
    if not isinstance(st, dict):
        errs.append("stance must be an object")
        st = {}
    if st and total_n:
        s = sum(int(st.get(k, 0) or 0) for k in
                ("answers", "entitled_refusals", "errors"))
        if s != total_n:
            errs.append(f"stance totals {s} != sum of bank n {total_n}")
    fr = cert.get("fabrication_rate")
    if rates and isinstance(fr, (int, float)):
        if not (min(rates) - 1e-9 <= fr <= max(rates) + 1e-9):
            errs.append("aggregate fabrication_rate outside per-bank "
                        "range")
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        if parse_dt(cert["issued"]) > now + datetime.timedelta(
                minutes=5):
            errs.append("issued time is in the future")
    except Exception:
        pass
    prov = cert.get("provenance", {}) or {}
    if effective == "issued" and prov.get("scorer_strict") is not True:
        errs.append("issued requires provenance.scorer_strict true")
    # datetimes must parse regardless of which schema engine ran
    for k in ("issued", "expires"):
        try:
            parse_dt(cert.get(k))
        except Exception:
            errs.append(f"{k} is not a parseable ISO-8601 datetime")
    for i, t in enumerate(cert.get("thresholds", []) or []):
        try:
            parse_dt(t.get("registered_at"))
        except Exception:
            errs.append(f"threshold[{i}].registered_at not parseable")
    return ("pass" if not errs else "fail", errs)


# ---------- signature ----------
def load_anchor(args):
    if args.issuer_key:
        return {"cli": args.issuer_key.lower()}
    if args.issuer_keys and args.issuer_keys.is_file():
        doc = json.loads(args.issuer_keys.read_text())
        return {k["key_id"]: k["public_key"].lower()
                for k in doc.get("keys", [])
                if k.get("status", "active") == "active"}
    return None


def verify_sig(payload, sig_hex, pub_hex):
    import nacl.signing
    import nacl.encoding
    vk = nacl.signing.VerifyKey(pub_hex,
                                encoder=nacl.encoding.HexEncoder)
    vk.verify(payload.encode(), bytes.fromhex(sig_hex))


def check_signature(cert, anchor):
    sig = cert.get("signature")
    if not sig:
        return "absent", None
    if anchor is None:
        return "no_trust_anchor", sig.get("key_id")
    kid = sig.get("key_id")
    trusted = (list(anchor.values()) if "cli" in anchor
               else [anchor[kid]] if kid in anchor else [])
    embedded = str(sig.get("public_key", "")).lower()
    if not trusted or (embedded and embedded not in trusted):
        return "untrusted_key", kid
    try:
        verify_sig(signed_payload(cert), sig["sig"], trusted[0])
        return "pass", kid
    except ImportError:
        return "unverifiable_no_pynacl", kid
    except Exception:
        return "fail", kid


# ---------- revocation (signed record) ----------
def check_revocation(cert, path, anchor):
    if path is None or not path.is_file():
        return "not_checked"
    rev = json.loads(path.read_text())
    # v2 signed form: {schema, payload{generated,next_update,
    #   revoked[], issuer_key_id}, signature{...}}
    if rev.get("schema") == "arcifact-revocation/2":
        pay = rev.get("payload", {})
        sig = rev.get("signature", {})
        state = "unauthenticated"
        if anchor:
            kid = sig.get("key_id")
            trusted = (list(anchor.values()) if "cli" in anchor
                       else [anchor.get(kid)] if kid in anchor else [])
            try:
                if trusted and trusted[0]:
                    verify_sig(canon(pay), sig.get("sig", ""),
                               trusted[0])
                    state = "authenticated"
            except Exception:
                return "fail"
        try:
            if parse_dt(pay.get("next_update")) < \
                    datetime.datetime.now(datetime.timezone.utc):
                return "stale"
        except Exception:
            return "stale"
        if cert.get("sha256") in (pay.get("revoked") or []):
            return "fail"
        return ("checked_not_revoked" if state == "authenticated"
                else "unauthenticated")
    # legacy unsigned form
    ids = rev.get("revoked", []) if isinstance(rev, dict) else rev
    if cert.get("sha256") in ids:
        return "fail"
    return "unauthenticated"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("cert", type=pathlib.Path)
    ap.add_argument("--schema", type=pathlib.Path)
    ap.add_argument("--issuer-keys", type=pathlib.Path)
    ap.add_argument("--issuer-key", type=str)
    ap.add_argument("--banks", type=pathlib.Path)
    ap.add_argument("--manifest-set", type=pathlib.Path)
    ap.add_argument("--manifest-dir", type=pathlib.Path)
    ap.add_argument("--revocation", type=pathlib.Path)
    ap.add_argument("--profile", choices=["issued", "report", "draft"])
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args(argv)
    cert = json.loads(args.cert.read_text())

    cert_profile = cert.get("profile", "report")
    req = args.profile or "draft"
    effective = (cert_profile if RANK.get(cert_profile, 1) >=
                 RANK.get(req, 0) else req)

    m = {"certificate_profile": cert_profile,
         "requested_profile": args.profile or "(none)",
         "effective_profile": effective,
         "canonicalization": CANON_ID}

    schema_state, schema_errs, engine = check_schema(cert, args.schema)
    m["schema"] = schema_state
    m["schema_engine"] = engine
    if effective == "issued" and engine != "jsonschema":
        m["schema"] = ("engine_unavailable"
                       if schema_state == "pass" else schema_state)

    m["seal"] = ("pass" if hmac.compare_digest(
        str(cert.get("sha256", "")),
        sha_hex(sealed_payload(cert).encode())) else "fail")

    sem_state, sem_errs = check_semantics(cert, effective)
    m["semantics"] = sem_state

    anchor = load_anchor(args)
    sig_state, key_id = check_signature(cert, anchor)
    m["issuer_signature"] = sig_state
    m["key_id"] = key_id

    if args.banks:
        fails = []
        for b in cert.get("banks", []) or []:
            f = args.banks / str(b.get("bank"))
            if not f.is_file():
                fails.append(f"{b.get('bank')}: absent")
            elif sha_hex(f.read_bytes()) != b.get("bank_sha256"):
                fails.append(f"{b.get('bank')}: digest mismatch")
        m["banks"] = "pass" if not fails else "fail"
        m["bank_fails"] = fails
    else:
        m["banks"] = "not_checked"

    if args.manifest_set and args.manifest_set.is_file():
        idx = json.loads(args.manifest_set.read_text())
        ok = idx.get("schema") == "arcifact-manifest-set/1"
        members = idx.get("members", []) if ok else []
        root = sha_hex(canon(
            [{"path": x["path"], "sha256": x["sha256"]}
             for x in members]).encode())
        claimed = cert.get("provenance", {}).get("manifest_root")
        ok = ok and root == claimed
        member_fail = []
        if ok and args.manifest_dir:
            for x in members:
                f = args.manifest_dir / x["path"]
                if not f.is_file():
                    member_fail.append(f"{x['path']}: absent")
                elif sha_hex(f.read_bytes()) != x["sha256"]:
                    member_fail.append(f"{x['path']}: byte mismatch")
        member_paths = {x["path"] for x in members}
        listed = {b.get("bank") for b in cert.get("banks", []) or []}
        if ok and not listed <= member_paths:
            member_fail.append("certificate banks not all in "
                               "manifest-set members")
        m["manifest_set"] = ("pass" if ok and not member_fail
                             else "fail")
        if member_fail:
            m["manifest_fails"] = member_fail
        m["manifest_members_verified"] = bool(args.manifest_dir)
    else:
        m["manifest_set"] = "not_checked"

    m["revocation"] = check_revocation(cert, args.revocation, anchor)

    try:
        di, de = parse_dt(cert["issued"]), parse_dt(cert["expires"])
        now = datetime.datetime.now(datetime.timezone.utc)
        m["expiry"] = ("fail" if de <= di else
                       "current" if now < de else "expired")
    except Exception:
        m["expiry"] = "fail"

    bars = cert.get("bars")
    m["bars_outcome"] = ("passed" if isinstance(bars, dict)
                         and bars.get("passed") is True else
                         "failed" if isinstance(bars, dict)
                         and bars.get("passed") is False else
                         "not_stated")

    hard_fail = (m["schema"] == "fail" or m["seal"] == "fail"
                 or m["semantics"] == "fail"
                 or m.get("banks") == "fail"
                 or m.get("manifest_set") == "fail"
                 or m.get("revocation") == "fail"
                 or m["expiry"] in ("fail", "expired")
                 or m["issuer_signature"] in ("fail", "untrusted_key"))

    issued_ok = (m["schema"] == "pass"
                 and m["schema_engine"] == "jsonschema"
                 and m["seal"] == "pass"
                 and m["semantics"] == "pass"
                 and m["issuer_signature"] == "pass"
                 and m.get("banks") == "pass"
                 and m.get("manifest_set") == "pass"
                 and m.get("revocation") == "checked_not_revoked"
                 and m["expiry"] == "current")

    if hard_fail:
        verdict = "INVALID"
    elif effective == "issued":
        verdict = "VALID" if issued_ok else "INCOMPLETE"
    else:
        base = (m["schema"] in ("pass",) and m["seal"] == "pass"
                and m["semantics"] == "pass"
                and m["expiry"] == "current"
                and m["issuer_signature"] in ("pass", "absent",
                                              "not_checked"))
        verdict = "SELF_CONSISTENT_REPORT" if base else "INCOMPLETE"

    out = {"matrix": m,
           "schema_errors": schema_errs if m["schema"] == "fail" else [],
           "semantic_errors": sem_errs if sem_state == "fail" else [],
           "verdict": verdict}
    print(json.dumps(out, indent=1 if args.pretty else None))
    return 0 if verdict in ("VALID", "SELF_CONSISTENT_REPORT") else 1


if __name__ == "__main__":
    raise SystemExit(main())
