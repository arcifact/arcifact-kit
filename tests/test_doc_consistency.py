"""Two documents describing the same capability must agree.

THE DEFECT THIS CATCHES

docs/WITNESS_CERTIFICATE.md said full recount was "available under
evaluation terms" while README.md said it is public and in this
repository. Both cannot be true. The README was corrected when the
capability was published; the certificate document was not.

A document describing a capability as withheld when it is published
tells a reader the wrong thing about what they are allowed to do, and it
is the kind of drift nobody notices because each file is correct on its
own terms.
"""
import os
import re

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _read(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        pytest.skip(f"{rel} not present")
    return open(p, encoding="utf-8").read()


def test_nothing_public_is_described_as_withheld():
    """Every tool in tools/ is in this repository by definition. No
    document may describe one as available only on request."""
    tools = {f for f in os.listdir(os.path.join(ROOT, "tools"))
             if f.endswith(".py")}
    docs = []
    for d in ("README.md",):
        docs.append((d, _read(d)))
    dd = os.path.join(ROOT, "docs")
    if os.path.isdir(dd):
        for f in sorted(os.listdir(dd)):
            if f.endswith(".md"):
                docs.append((f"docs/{f}", _read(f"docs/{f}")))
    WITHHELD = re.compile(
        r"(available under evaluation terms|on request only|"
        r"not included in this repository|private and available)",
        re.I)
    # A CORRECTION QUOTES THE THING IT CORRECTS.
    #
    # The first version of this check flagged the sentence explaining
    # that the old wording was wrong, because that sentence necessarily
    # contains the old wording. A test that cannot tell a correction
    # from the defect will be suppressed rather than fixed, so a line
    # that also carries a correction marker is not a finding.
    CORRECTED = re.compile(
        r"(said it was|until \d{4}-\d{2}-\d{2}|was true once|"
        r"used to be described|this paragraph)", re.I)
    bad = []
    for name, src in docs:
        for m in WITHHELD.finditer(src):
            window = src[max(0, m.start() - 320):m.end() + 320]
            if CORRECTED.search(window):
                continue
            for t in tools:
                if t in window or t.replace(".py", "") in window:
                    bad.append(f"{name}: describes {t} as withheld")
    assert not bad, (
        "these documents describe a PUBLISHED tool as withheld: "
        + "; ".join(sorted(set(bad))))


def test_the_licence_is_not_called_open_source():
    """The evaluation licence is not an OSI licence. Source-available
    and publicly inspectable are accurate; open source is a term with a
    definition somebody will hold us to."""
    bad = []
    for rel in ["README.md"] + [
            f"docs/{f}" for f in os.listdir(os.path.join(ROOT, "docs"))
            if f.endswith(".md")] if os.path.isdir(
                os.path.join(ROOT, "docs")) else ["README.md"]:
        src = _read(rel)
        if re.search(r"open[\s-]source", src, re.I):
            bad.append(rel)
    assert not bad, (
        f"{bad} call this open source. The evaluation licence is not an "
        f"OSI licence; say source-available.")


def test_every_tool_referenced_in_the_readme_exists():
    """A README naming a tool that is not here is a promise the
    repository does not keep."""
    src = _read("README.md")
    named = set(re.findall(r"tools/(\w+\.py)", src))
    missing = [t for t in sorted(named)
               if not os.path.exists(os.path.join(ROOT, "tools", t))]
    assert not missing, f"README names tools that do not exist: {missing}"


# --------------------------- the README must route, and its links work

def test_the_readme_routes_before_it_explains():
    """The reviewer: the combined README dilutes the immediate Gate
    story. Gate appeared at section 11 of 16, behind eleven sections of
    model evaluation, in the repository that is the entry point for
    anybody checking a Gate report."""
    src = _read("README.md")
    heads = re.findall(r"^#{2,3} (.+)$", src, re.M)
    assert heads, "no sections"
    first = " ".join(heads[:4]).lower()
    assert "gate report" in first, (
        "a reader with a Gate report must be routed in the first "
        "screen, not at section 11")


def test_every_in_page_anchor_resolves():
    """A routing block whose links do not land is worse than no routing
    block: it moves a reader and then loses them."""
    src = _read("README.md")
    heads = {re.sub(r"[^a-z0-9 -]", "", h.lower()).replace(" ", "-")
             for h in re.findall(r"^#{1,6} (.+)$", src, re.M)}
    bad = [a for a in re.findall(r"\]\(#([a-z0-9-]+)\)", src)
           if a not in heads]
    assert not bad, f"anchors that do not resolve: {bad}"


def test_the_canonical_verify_command_names_a_real_tool():
    """One command, before the model-evaluation content. If it names a
    script that is not here the first thing a reviewer runs fails."""
    src = _read("README.md")
    m = re.search(r"python3 (tools/\w+\.py)", src)
    assert m, "no canonical verify command in the README"
    assert os.path.exists(os.path.join(ROOT, m.group(1))), m.group(1)
