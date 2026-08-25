"""A record must bind the instrument whose evidence it carries.

WHY THIS CHECK EXISTS

A shipped record carried counterexample evidence without naming
counterexample.py's digest. That asserts newer evidence under an older
instrument: the record says "here is what the analyser found" while
binding a version of the analyser that could not have found it.

The commitment log exists to prevent exactly that, and the log did not
catch it, because the log binds what the record DECLARES rather than
checking the declaration is complete.

WHY THESE TESTS EXIST

The check has been in the verifier for some time with no test at all. A
check nobody exercises is a check that quietly stops working, and this
one guards the property the whole evidence architecture rests on.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))

import verify_report as V


class _Res:
    """The verifier's result sink, reduced to what these assert."""

    def __init__(self):
        self.fails = []
        self.incompletes = []
        self.notes = []

    def fail(self, m):
        self.fails.append(m)

    def incomplete(self, m):
        self.incompletes.append(m)

    def note(self, m):
        self.notes.append(m)


def _rec(payload=None, envelope=None, digests=None):
    return {"payload": payload or {}, "envelope": envelope or {},
            "provenance": {"tool_digests": digests or {}}}


def test_evidence_without_its_instrument_fails():
    """THE SHIPPED DEFECT. A record carrying counterexamples that does
    not bind counterexample.py."""
    res = _Res()
    V.check_feature_bindings(_rec(payload={"counterexamples": [{"x": 1}]}), res)
    assert res.fails
    assert "counterexample.py" in res.fails[0]
    assert "post-dates the instrument" in res.fails[0]


def test_evidence_with_its_instrument_passes():
    res = _Res()
    V.check_feature_bindings(
        _rec(payload={"counterexamples": [{"x": 1}]},
             digests={"counterexample.py": "abc123"}), res)
    assert not res.fails


def test_a_path_keyed_digest_still_counts():
    """The build manifest keys modules by path, so witness/repo.py must
    satisfy a binding for repo.py. Matching on the full key only would
    fail every record the current manifest produces."""
    res = _Res()
    V.check_feature_bindings(
        _rec(payload={"repository_level": {"n": 3}},
             digests={"witness/repo.py": "deadbeef"}), res)
    assert not res.fails


def test_evidence_in_the_envelope_counts_as_evidence():
    """A component's output can arrive in either half of the record.
    Checking only the payload would let the envelope carry unbound
    evidence."""
    res = _Res()
    V.check_feature_bindings(
        _rec(envelope={"sensitivity": {"delta": 0.2}}), res)
    assert res.fails
    assert "sensitivity.py" in res.fails[0]


@pytest.mark.parametrize("key,comp", sorted(V.FEATURE_COMPONENTS.items()))
def test_every_declared_component_is_actually_enforced(key, comp):
    """A component in the map that nothing checks is decoration. This
    fails for any entry that can carry evidence without binding."""
    res = _Res()
    V.check_feature_bindings(_rec(payload={key: {"present": True}}), res)
    assert res.fails, f"{key} can carry evidence without binding {comp}"


def test_an_empty_feature_is_not_treated_as_present():
    """A key present but empty is not evidence, and demanding a binding
    for it would fail correct records."""
    res = _Res()
    V.check_feature_bindings(_rec(payload={"counterexamples": []}), res)
    assert not res.fails


def test_a_record_with_no_features_needs_no_bindings():
    res = _Res()
    V.check_feature_bindings(_rec(), res)
    assert not res.fails
