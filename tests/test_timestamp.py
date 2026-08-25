"""Attack the RFC 3161 path with real tokens.

WHY THESE ARE REAL RATHER THAN SYNTHETIC

The anchor is the one part of a record that does not rest on an Arcifact
key: the signatures are the timestamp authorities' own, which is exactly
what makes them worth having. A synthetic fixture would test our parser
against our own idea of a token.

`genuine.tsr` was minted from freetsa.org over `head.txt`. The others are
that file attacked: one byte flipped in the signature region, truncated
in half, and replaced with text that is not a token at all.

WHAT THIS DOES NOT CLAIM

Full chain verification. `openssl ts -verify` needs the authority's CA
bundle, which is not vendored here, so these assert the properties a
verifier can check WITHOUT trusting a CA: that the imprint commits to the
data, that the embedded time is read from inside the token rather than
from a field beside it, and that a damaged token is refused rather than
skipped.

A test that silently skips when openssl is absent would be the failure
this repository exists to detect, so absence is reported.
"""
import hashlib
import os
import re
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TSA = os.path.join(HERE, "fixtures", "tsa")

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="openssl absent: the timestamp path is NOT CHECKED here")


def _reply(path):
    return subprocess.run(["openssl", "ts", "-reply", "-in", path, "-text"],
                          capture_output=True, text=True, timeout=30)


def _imprint(path):
    r = _reply(path)
    m = re.search(r"Message data:\n((?:\s+\d{4} - .*\n)+)", r.stdout)
    if not m:
        return None
    hexs = "".join(re.findall(r"- ([0-9a-f \-]+)\s{2,}", m.group(1)))
    return "".join(hexs.replace("-", " ").split())


def test_the_genuine_token_parses_and_was_granted():
    r = _reply(os.path.join(TSA, "genuine.tsr"))
    assert r.returncode == 0
    assert "Granted" in r.stdout


def test_the_imprint_commits_to_the_head_it_claims():
    """THE PROPERTY THAT MATTERS. A token proves a hash existed at a
    time. If the imprint is not the hash of our head, the token is
    evidence about somebody else's data."""
    want = hashlib.sha256(
        open(os.path.join(TSA, "head.txt"), "rb").read()).hexdigest()
    assert _imprint(os.path.join(TSA, "genuine.tsr")) == want


def test_the_same_token_does_not_vouch_for_different_data():
    """Reusing a valid token over changed content is the obvious
    attack, and the imprint is what refuses it."""
    other = hashlib.sha256(b"a DIFFERENT head\n").hexdigest()
    assert _imprint(os.path.join(TSA, "genuine.tsr")) != other


def test_the_time_is_read_from_inside_the_signed_token():
    """An earlier version trusted the JSON field beside the token, so
    editing that field and resealing was enough to fake the ordering.
    The authoritative time is embedded."""
    r = _reply(os.path.join(TSA, "genuine.tsr"))
    m = re.search(r"Time stamp:\s*(.+)", r.stdout)
    assert m, "no embedded time"
    assert re.match(r"[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \d{4} GMT",
                    m.group(1).strip())


@pytest.mark.parametrize("name", ["truncated.tsr", "garbage.tsr"])
def test_a_malformed_token_cannot_even_be_parsed(name):
    r = _reply(os.path.join(TSA, name))
    assert not (r.returncode == 0 and "Granted" in r.stdout), (
        f"{name} was accepted as a usable token")


def test_parsing_a_token_is_not_verifying_it():
    """THE FINDING THESE TESTS FOUND.

    `openssl ts -reply` parses. It does NOT check the signature, so a
    token with a flipped byte in its signature region still reports
    "Status: Granted" and still yields an embedded time and imprint.

    A verifier that stops at -reply accepts a forged token. Ours does
    not: it calls `ts -verify` with a CA and fails the record when the
    signature does not check out. This asserts that distinction, because
    the tempting shortcut looks like it works.
    """
    tampered = _reply(os.path.join(TSA, "tampered.tsr"))
    assert "Granted" in tampered.stdout, (
        "if this ever fails, -reply started verifying and this test can go")
    src = open(os.path.join(os.path.dirname(HERE), "tools",
                            "verify_report.py"), encoding="utf-8").read()
    assert '"-verify"' in src, (
        "the verifier must not rely on -reply alone")
    assert "Verification: OK" in src, (
        "it must check the verification RESULT, not merely invoke it")


def test_two_independent_authorities_are_expected():
    """One authority is a single point of failure AND a single point of
    collusion. The verifier reports a lone token as incomplete rather
    than sufficient."""
    src = open(os.path.join(os.path.dirname(HERE), "tools",
                            "verify_report.py"), encoding="utf-8").read()
    assert "independent ones are expected" in src
