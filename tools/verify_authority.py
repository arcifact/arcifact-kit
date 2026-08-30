#!/usr/bin/env python3
"""Verify an Arcifact Authority record: self-consistency offline, the register with --refetch, a listed issuer key with --issuer-key, and a Bitcoin timestamp when anchored.

  python3 verify_authority.py RECORD.authority.json --sources DIR

DIR holds your own copies: the document, its extracted text, and the
register files the record binds (as fetched from Find Case Law and
legislation.gov.uk). Nothing here imports the checker. The script
recomputes, from those bytes alone:

  1. the seal: sha256 over the record with the seal removed
  2. every source binding: the digest of your copy equals the record's
  3. for every judgment binding, the register's own content hash inside
     the XML equals the one the record quotes
  4. every register claim: the XML carries the citation the claim names
  5. every name claim: the same word comparison, reproduced here
  6. every pinpoint claim: the paragraph number is present in the XML
  7. every quotation claim: the normalised words are a substring of the
     normalised paragraph (or judgment) text, exactly as the record says
  8. every section claim: the section XML exists and carries the
     subsection where one is claimed
  9. honesty: every unresolved claim names what would settle it, and
     the envelope declares something out of scope

A missing source is INCOMPLETE, named. A verdict that does not recompute
is INVALID, named. Nothing here passes on evidence it did not have.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import unicodedata
import xml.etree.ElementTree as ET
import zipfile

AKN = "http://docs.oasis-open.org/legaldocml/ns/akn/3.0"
UK = "https://caselaw.nationalarchives.gov.uk/akn"
LEG = "http://www.legislation.gov.uk/namespaces/legislation"
NS = {"akn": AKN, "uk": UK, "leg": LEG}

STOP = {"the", "of", "on", "application", "r", "v", "and", "an", "a", "in", "re", "for", "ltd", "limited", "plc",
        "llp", "inc", "co", "company", "anor", "ors", "others", "another", "by", "his", "her", "their", "its",
        "mr", "mrs", "ms", "dr", "no", "nos", "at", "to", "as", "is", "with", "from", "under", "regina", "rex"}
ABBREV = {"lbc": ["london", "borough"], "bc": ["borough", "council"], "dc": ["district", "council"],
          "cc": ["county", "council"], "mbc": ["metropolitan", "borough", "council"],
          "sshd": ["secretary", "state", "home", "department"], "hmrc": ["commissioners", "revenue", "customs"],
          "sra": ["solicitors", "regulation", "authority"], "nhs": ["nhs"], "uk": ["uk"],
          "ico": ["information", "commissioner"], "sswp": ["secretary", "state", "work", "pensions"],
          "sos": ["secretary", "state"]}


class R:
    def __init__(self):
        self.fail, self.inc, self.ok = [], [], []


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


MAX_XML = 60 * 1024 * 1024
MAX_PART = 50 * 1024 * 1024


def safe_bytes(b, what):
    """The same hostile-input policy as the checker: no DOCTYPE, no entity
    declarations, bounded size. A verification bundle comes from somebody
    else, so it gets no more trust than a register reply."""
    if len(b) > MAX_XML:
        raise ValueError(f"{what} is {len(b)} bytes; refused")
    low = b.lower()
    if b"<!doctype" in low[:4096] or b"<!entity" in low:
        raise ValueError(f"{what} carries a DOCTYPE or entity declaration; refused")
    return b


def safe_xml(b, what):
    return ET.fromstring(safe_bytes(b, what))


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def normalise(s):
    s = unicodedata.normalize("NFKC", s)
    for k, v in {"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2013": "-", "\u2014": "-"}.items():
        s = s.replace(k, v)
    s = re.sub(r"[^a-z0-9 ]+", " ", s.lower())
    return re.sub(r"\s+", " ", s).strip()


# ---- case names: copied verbatim from authority/names.py so the verifier recomputes what the checker computed
_ABBR = {
    "ltd": "limited", "plc": "plc", "llp": "llp", "co": "company", "corp": "corporation", "inc": "incorporated",
    "bros": "brothers", "sos": "secretary of state", "sshd": "secretary of state for the home department",
    "ssj": "secretary of state for justice", "hmrc": "commissioners for his majestys revenue and customs",
    "dpp": "director of public prosecutions", "cps": "crown prosecution service", "sra": "solicitors regulation authority",
    "bsb": "bar standards board", "lbc": "london borough council", "bc": "borough council", "cc": "county council",
    "dc": "district council", "rbkc": "royal borough of kensington and chelsea", "nhs": "national health service",
    "uk": "united kingdom", "hm": "his majestys", "hmg": "his majestys government",
}
_GENERIC = {"the", "of", "and", "for", "a", "an", "in", "on", "at", "by", "to", "his", "her", "majestys", "majesty", "de", "le", "la", "du", "von", "van",
            "limited", "plc", "llp", "company", "corporation", "incorporated",
            "council", "borough", "county", "district", "city", "london", "secretary", "state", "department", "commissioners", "revenue", "customs",
            "director", "public", "prosecutions", "crown", "prosecution", "service", "authority", "board", "trust", "foundation", "national", "health",
            "mr", "mrs", "ms", "miss", "dr", "sir", "lord", "lady", "qc", "kc", "others", "ors", "anor", "another", "anr", "intervening", "interested", "party"}
_MISC = {"ors", "others", "anor", "another", "anr", "intervening", "interested", "party", "parties"}
_INSTITUTION = {"ltd", "limited", "plc", "llp", "co", "company", "corp", "corporation", "inc", "incorporated", "holdings", "group", "council", "borough",
                "authority", "bank", "trust", "board", "commissioners", "secretary", "department", "ministry", "university", "college", "school", "hospital",
                "nhs", "hmrc", "sshd", "sos", "association", "society", "partnership", "partners", "bros", "brothers", "international", "services", "finance",
                "insurance", "assurance", "fund", "trustees", "trustee", "lbc", "bc", "cc", "dc", "borough"}
_V = re.compile(r"\s+(?:v|v\.|-v-|vs|vs\.|versus)\s+", re.IGNORECASE)


def _norm(s):
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    s = s.lower().replace("&", " and ").replace("'", "").replace("\u2019", "")
    s = re.sub(r"\(\s*(?:on the application of|otao|oao)\s*", "(", s)
    s = re.sub(r"[^a-z0-9()\[\] ]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _tokens(party):
    out = []
    for t in _norm(party).replace("(", " ").replace(")", " ").split():
        if t in _ABBR:
            out.extend(_ABBR[t].split())
        else:
            out.append(t)
    return out


def _material(tokens):
    # an anonymised party is one letter ('A', 'X') and is material; a stray letter inside a longer name is not
    if len(tokens) == 1:
        return [t for t in tokens if t not in _GENERIC]
    return [t for t in tokens if t not in _GENERIC and len(t) >= 2]


def _split_parties(side):
    """'Smith and Jones', 'Smith, Jones & Ors', 'Gover & Ors' -> parties, misc dropped."""
    s = _norm(side)
    s = re.sub(r"\b(?:and|,)\s*(?:" + "|".join(_MISC) + r")\b", " ", s)
    s = re.sub(r"\b(?:" + "|".join(_MISC) + r")\b", " ", s)
    # 'and' separates parties, except inside one company's name: a side with no comma that ends in an
    # institution marker (Ltd, plc, LLP, Bank ...) is one party, 'Lighting and Lamps UK Ltd'
    toks = s.split()
    if "," not in s and toks and toks[-1] in _INSTITUTION:
        return [s]
    parts = [p.strip() for p in re.split(r",| and ", s) if p.strip()]
    # rejoin 'x and y' company names when a part is a single generic token
    out = []
    for p in parts:
        if out and (len(_material(_tokens(p))) == 0):
            out[-1] = out[-1] + " and " + p
        else:
            out.append(p)
    return out


def parse_name(name):
    """{'form': 'v'|'re'|'flat', 'left': [parties], 'right': [parties], 'applicant': str|None, 'crown': bool}"""
    n = re.sub(r"\s+", " ", name or "").strip()
    n = re.sub(r"\s*\[[^\]]*\]\s*$", "", n)          # trailing [2014] EWHC ... if any
    n = re.sub(r"\s*\((?:No\.?\s*\d+|Costs|Interim|Permission)\)\s*$", "", n, flags=re.IGNORECASE)
    if re.match(r"^(?:in\s+)?(?:re|in the matter of|in re)\b", n, re.IGNORECASE):
        body = re.sub(r"^(?:in\s+)?(?:re|in the matter of|in re)\s+", "", n, flags=re.IGNORECASE)
        return {"form": "re", "left": _split_parties(body), "right": [], "applicant": None, "crown": False}
    parts = _V.split(n, maxsplit=1)
    if len(parts) != 2:
        return {"form": "flat", "left": _split_parties(n), "right": [], "applicant": None, "crown": False}
    left, right = parts
    applicant = None
    crown = False
    m = re.match(r"^\s*(?:r|the king|the queen|rex|regina|the crown)\s*(?:\((.*)\))?\s*$", left, re.IGNORECASE)
    if m:
        crown = True
        applicant = m.group(1)
    else:
        # the register's own form: 'Ayinde, R (On the Application Of) v Haringey'
        m3 = re.match(r"^\s*(.+?),\s*(?:r|the king|the queen)\s*\(\s*on the application of\s*\)\s*$", left, re.IGNORECASE)
        if m3:
            crown = True
            applicant = m3.group(1)
    # 'R v Y ex parte X'
    m2 = re.search(r"\bex\s*p(?:arte)?\.?\s+(.+)$", right, re.IGNORECASE)
    if crown and m2 and not applicant:
        applicant = m2.group(1)
        right = right[:m2.start()]
    if applicant:
        applicant = re.sub(r"^\s*(?:on the application of|otao|oao)\s*", "", applicant.strip(), flags=re.IGNORECASE).strip() or None
    lp = [] if crown else _split_parties(left)
    return {"form": "v", "left": lp, "right": _split_parties(right), "applicant": applicant, "crown": crown}


HOLDS = ("exact", "normalised_exact", "surname_short_form", "institutional_abbreviation", "leading_tokens")
_RANK = {"exact": 0, "normalised_exact": 1, "institutional_abbreviation": 2, "surname_short_form": 3, "leading_tokens": 4, "token_subset": 5}


def _party_class(given, register):
    """The class under which a given party maps to a register party, or None."""
    g, r = _material(_tokens(given)), _material(_tokens(register))
    if not g:
        return "normalised_exact"                     # nothing material to test ("the council")
    if not r:
        return None
    raw = [t for t in _norm(given).replace("(", " ").replace(")", " ").split()]
    # an abbreviation form is made of abbreviations (and generic words) that expand to the register's party
    if any(t in _ABBR for t in raw) and all(t in _ABBR or t in _GENERIC for t in raw) and all(t in r for t in g):
        return "institutional_abbreviation"
    if g == r:
        return "normalised_exact"
    # a surname stands for a person, never for a company or an institution
    rraw = _norm(register).replace("(", " ").replace(")", " ").split()
    person = not any(t in _INSTITUTION for t in rraw)
    if person and len(g) == 1 and g[0] == r[-1] and len(r) >= 2:
        return "surname_short_form"
    if r[:len(g)] == g:
        return "leading_tokens"
    if all(t in r for t in g):
        return "token_subset"
    return None


def _party_maps(given, register):
    return _party_class(given, register) is not None


def _edit1(a, b):
    """True when a and b differ by one character (substitution, insertion or deletion)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    s, l = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(l)):
        if l[:i] + l[i + 1:] == s:
            return True
    return False


def _spelling(given_party, register_party):
    g, r = _material(_tokens(given_party)), _material(_tokens(register_party))
    if len(g) != len(r) or not g:
        return False
    diffs = [(x, y) for x, y in zip(g, r) if x != y]
    return len(diffs) == 1 and len(diffs[0][0]) >= 6 and _edit1(diffs[0][0], diffs[0][1])


def _rejoin(given_side, register_side):
    """'Lighting and Lamps' against one register party 'Lighting and Lamps UK Ltd': the side that split on
    'and' is one name when its joined form maps to the other side's single party."""
    if len(register_side) == 1 and len(given_side) > 1:
        joined = " and ".join(given_side)
        if _party_class(joined, register_side[0]) is not None:
            return [joined], register_side
    if len(given_side) == 1 and len(register_side) > 1:
        joined = " and ".join(register_side)
        if _party_class(given_side[0], joined) is not None:
            return given_side, [joined]
    return given_side, register_side


def _match_sides(given_side, register_side):
    """Returns (unmatched_given, unmatched_register, weakest_class)."""
    given_side, register_side = _rejoin(given_side, register_side)
    remaining = list(register_side)
    unmatched_given = []
    weakest = "normalised_exact"
    for gp in given_side:
        best = None
        for rp in remaining:
            c = _party_class(gp, rp)
            if c is not None and (best is None or _RANK[c] < _RANK[best[1]]):
                best = (rp, c)
        if best is None:
            unmatched_given.append(gp)
        else:
            remaining.remove(best[0])
            if _RANK[best[1]] > _RANK[weakest]:
                weakest = best[1]
    return unmatched_given, remaining, weakest


def compare_names(given, register):
    """See the module docstring. Returns {'verdict', 'class', 'detail'}."""
    if not given or not register:
        return {"verdict": "unresolved", "class": "ambiguous", "detail": "a name is empty"}
    if re.sub(r"\s+", " ", given.strip().lower()) == re.sub(r"\s+", " ", register.strip().lower()):
        return {"verdict": "holds", "class": "exact", "detail": ""}
    if _norm(given) == _norm(register):
        return {"verdict": "holds", "class": "normalised_exact", "detail": ""}
    g, r = parse_name(given), parse_name(register)
    if g["form"] == "v" and r["form"] == "v":
        # judicial review: the applicant is the material party
        if g["crown"] and r["crown"]:
            if r["applicant"] and not g["applicant"]:
                ug, ur, _w = _match_sides(g["right"], r["right"])
                if not ug:
                    return {"verdict": "unresolved", "class": "party_missing", "detail": f"the register names an applicant, '{r['applicant']}', which the document omits"}
            if g["applicant"] and r["applicant"] and not _party_maps(g["applicant"], r["applicant"]):
                return {"verdict": "fails", "class": "party_substituted", "detail": f"applicant '{g['applicant']}' is not the register's '{r['applicant']}'"}
            if g["applicant"] and not r["applicant"]:
                return {"verdict": "fails", "class": "party_added", "detail": f"the document names an applicant, '{g['applicant']}', which the register does not"}
        # the Crown's side is the applicant, when there is one: 'Ayinde v Haringey'
        # names the applicant of 'R (Ayinde) v Haringey'
        g_left = ([g["applicant"]] if g["applicant"] else []) if g["crown"] else g["left"]
        r_left = ([r["applicant"]] if r["applicant"] else []) if r["crown"] else r["left"]
        ug_l, ur_l, w_l = _match_sides(g_left, r_left)
        ug_r, ur_r, w_r = _match_sides(g["right"], r["right"])
        if not ug_l and not ug_r:
            more = ur_l or ur_r
            weakest = w_l if _RANK[w_l] >= _RANK[w_r] else w_r
            note = ("the register also names " + ", ".join(more) + "; " if more else "")
            if weakest == "token_subset":
                return {"verdict": "unresolved", "class": "token_subset", "detail": note + "a party is cited by words that are not the register's leading words; compare the names yourself"}
            return {"verdict": "holds", "class": weakest, "detail": (note + {"surname_short_form": "a party cited by surname", "institutional_abbreviation": "a recognised abbreviation", "leading_tokens": "a party cited by its leading words"}.get(weakest, "")).strip("; ")}
        # the sides swapped, as on appeal
        sg_l, sr_l, _ = _match_sides(g_left, r["right"])
        sg_r, sr_r, _ = _match_sides(g["right"], r_left)
        if not sg_l and not sg_r and g_left and g["right"]:
            return {"verdict": "holds", "class": "reversed_caption", "detail": "the parties appear in the opposite order, as on appeal"}
        bad = ug_l + ug_r
        unmatched_reg = ur_l if ug_l else ur_r
        if unmatched_reg:
            if _spelling(bad[0], unmatched_reg[0]):
                return {"verdict": "fails", "class": "spelling_variant", "detail": f"'{bad[0]}' is spelt '{unmatched_reg[0]}' in the register"}
            return {"verdict": "fails", "class": "party_substituted", "detail": f"'{bad[0]}' is not the register's '{unmatched_reg[0]}'"}
        return {"verdict": "fails", "class": "party_added", "detail": f"the document names '{bad[0]}', which the register's name does not"}
    if g["form"] == "re" and r["form"] == "re":
        ug, ur, w = _match_sides(g["left"], r["left"])
        if not ug:
            if w == "token_subset":
                return {"verdict": "unresolved", "class": "token_subset", "detail": "cited by words that are not the register's leading words"}
            return {"verdict": "holds", "class": w, "detail": ("the register also names " + ", ".join(ur)) if ur else ""}
        return {"verdict": "fails", "class": "party_substituted" if ur else "party_added", "detail": f"'{ug[0]}' is not in the register's name"}
    # a bare name against a two-sided register name: the profession knows a case
    # by its applicant or first-named party; a respondent's name alone is not a match
    if g["form"] == "flat" and r["form"] == "v":
        bare = " ".join(g["left"]) if g["left"] else given
        c = _party_class(bare, r["applicant"]) if r["applicant"] else None
        if c in HOLDS:
            return {"verdict": "holds", "class": c, "detail": "the applicant's name alone"}
        cs = [_party_class(bare, rp) for rp in r["left"]]
        if any(x in HOLDS for x in cs):
            return {"verdict": "holds", "class": next(x for x in cs if x in HOLDS), "detail": "the first-named party alone"}
        if c == "token_subset" or "token_subset" in cs:
            return {"verdict": "unresolved", "class": "token_subset", "detail": "some words of a party's name, not its leading words; compare the names yourself"}
        if any(_party_maps(bare, rp) for rp in r["right"]):
            return {"verdict": "unresolved", "class": "ambiguous", "detail": "a respondent's name alone; the case is known by its applicant or claimant"}
        return {"verdict": "fails", "class": "party_substituted", "detail": "not a party in the register's name"}
    # forms differ otherwise: material-token overlap, never holds on a partial
    gt, rt = set(_material(_tokens(given))), set(_material(_tokens(register)))
    if gt and rt and gt <= rt:
        return {"verdict": "unresolved", "class": "token_subset", "detail": "the given name's words are among the register's, but the forms differ; compare the names yourself"}
    if gt and rt and not (gt & rt):
        return {"verdict": "fails", "class": "party_substituted", "detail": "no material word in common"}
    return {"verdict": "unresolved", "class": "ambiguous", "detail": "the names could not be parsed into parties; compare them yourself"}


def txt(e):
    return re.sub(r"\s+", " ", "".join(e.itertext())).strip()


def parse_judgment(path):
    root = safe_xml(open(path, 'rb').read(), os.path.basename(path))
    cite = root.find(".//uk:cite", NS)
    name = root.find(".//akn:FRBRWork/akn:FRBRname", NS)
    h = root.find(".//uk:hash", NS)
    paras = {}
    for p in root.findall(".//akn:paragraph", NS):
        num = p.find("akn:num", NS)
        body = p.find("akn:content", NS)
        if num is not None and num.text:
            m = re.search(r"\d+", num.text)
            if m:
                paras.setdefault(int(m.group()), txt(body) if body is not None else txt(p))
    body = root.find(".//akn:judgmentBody", NS)
    return {"cite": cite.text.strip() if cite is not None and cite.text else None,
            "name": name.attrib.get("value") if name is not None else None,
            "hash": h.text.strip() if h is not None and h.text else None,
            "paras": paras, "text": txt(body) if body is not None else txt(root)}


def segments(q):
    parts = re.split(r"\s*(?:\.\s*\.\s*\.|\u2026)\s*", q)
    return [normalise(p) for p in parts if normalise(p)]


def in_order(segs, hay):
    pos = 0
    for s in segs:
        i = hay.find(s, pos)
        if i < 0:
            return False
        pos = i + len(s)
    return True


def quote_status(j, quote, para):
    segs = segments(quote)
    if para is not None and para in j["paras"] and in_order(segs, normalise(j["paras"][para])):
        return "verbatim", para
    for n, t in sorted(j["paras"].items()):
        if in_order(segs, normalise(t)):
            return ("verbatim" if para is None else "elsewhere"), n
    if in_order(segs, normalise(j["text"])):
        return ("verbatim" if para is None else "elsewhere"), None
    return "absent", None


def _part(z, name):
    info = z.getinfo(name)
    if info.file_size > MAX_PART:
        raise ValueError(f"{name} is {info.file_size} bytes; refused")
    return safe_bytes(z.read(name), name)


def docx_text(path):
    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    z = zipfile.ZipFile(path)
    names = z.namelist()
    if len(names) != len(set(names)):
        raise ValueError("docx has duplicate entries; refused")
    if any(n.startswith("/") or ".." in n.split("/") for n in names):
        raise ValueError("docx has traversal entries; refused")

    def paras(root):
        out = []
        for p in root.iter(W + "p"):
            parts = []
            for n in p.iter():
                if n.tag == W + "t" and n.text:
                    parts.append(n.text)
                elif n.tag == W + "tab":
                    parts.append("\t")
                elif n.tag in (W + "br", W + "cr"):
                    parts.append("\n")
                elif n.tag == W + "footnoteReference":
                    parts.append(f"[fn {n.attrib.get(W + 'id', '?')}]")
                elif n.tag == W + "endnoteReference":
                    parts.append(f"[en {n.attrib.get(W + 'id', '?')}]")
            t = "".join(parts).strip()
            if t:
                out.append(t)
        return out
    body = paras(ET.fromstring(_part(z, "word/document.xml")))
    notes = []
    for part, label in (("word/footnotes.xml", "Footnote"), ("word/endnotes.xml", "Endnote")):
        if part in z.namelist():
            root = ET.fromstring(_part(z, part))
            tag = W + ("footnote" if label == "Footnote" else "endnote")
            for n in root.iter(tag):
                nid = n.attrib.get(W + "id", "?")
                if nid in ("-1", "0"):
                    continue
                ps = paras(n)
                if ps:
                    notes.append(f"{label} {nid}: " + " ".join(ps))
    return "\n\n".join(body + notes)


def verify(path, sources):
    res = R()
    rec = json.load(open(path))
    if rec.get("schema") != "arcifact-report/1" or rec.get("instrument") != "authority":
        res.fail.append("not an arcifact-report/1 authority record")
        return res, rec
    # 1 seal
    body = {k: v for k, v in rec.items() if k not in ("sha256", "signature", "anchor")}
    if hashlib.sha256(canon(body)).hexdigest() != rec.get("sha256"):
        res.fail.append("seal does not recompute: the record was altered after sealing")
    # 2 bindings
    local = {}
    for b in rec["source_bindings"]:
        p = os.path.join(sources, os.path.basename(b["path"]))
        if not os.path.exists(p):
            res.inc.append(f"source not found locally: {b['path']}")
            continue
        got = sha_file(p)
        if got != b["sha256"]:
            res.fail.append(f"source mismatch: {b['path']} binds {b['sha256'][:12]}, your copy is {got[:12]}")
        else:
            res.ok.append(f"binding verified: {b['path']}")
            local[b["path"]] = p
    # extracted text consistency with the document, where we can recompute it
    doc_b = rec["source_bindings"][0]
    ext_b = rec["source_bindings"][1]
    if doc_b["path"] in local and ext_b["path"] in local:
        dp = local[doc_b["path"]]
        ext = open(local[ext_b["path"]], encoding="utf-8").read()
        recomputed = None
        if dp.lower().endswith(".docx"):
            try:
                recomputed = docx_text(dp)
            except ValueError as e:
                res.fail.append(f"document refused by the hostile-input policy: {e}")
        elif not dp.lower().endswith((".pdf", ".html", ".htm")):
            recomputed = open(dp, "rb").read().decode("utf-8", errors="replace")
        if recomputed is not None:
            if recomputed == ext:
                res.ok.append("extracted text recomputed from the document: identical")
            else:
                res.fail.append("extracted text does not match what this verifier extracts from the document")
        else:
            res.inc.append("extracted text not recomputable here (pdf/html extractor not reproduced); bound by digest only")
        # every authority span must be the cited text
        for a in rec["payload"]["authorities"]:
            texts = a.get("span_texts") or [a["as_cited"]] * len(a["spans"])
            for (s, e), want in zip(a["spans"], texts):
                if ext[s:e] != want and normalise(ext[s:e]) != normalise(want):
                    res.fail.append(f"{a['id']}: span {s}:{e} in the extracted text is {ext[s:e]!r}, not {want!r}")
    # 3-8 claims
    auth = {a["id"]: a for a in rec["payload"]["authorities"]}
    judg_cache = {}

    def judgment_for(aid):
        a = auth.get(aid, {})
        b = (a.get("register") or {}).get("binding")
        if not b:
            return None, "no register binding"
        if b not in local:
            return None, f"register file not local: {b}"
        if b not in judg_cache:
            judg_cache[b] = parse_judgment(local[b])
        return judg_cache[b], None

    for c in rec["claims"]:
        cid, v, aid = c["id"], c["verdict"], c.get("authority")
        a = auth.get(aid, {})
        kind = a.get("kind")
        if v == "unresolved" and not c.get("settled_by"):
            res.fail.append(f"{cid}: unresolved without settled_by")
        if cid.endswith(".exists"):
            if v != "unresolved":
                res.fail.append(f"{cid}: the instrument may not decide this claim, yet the verdict is {v}")
            continue
        if cid.endswith(".in_force"):
            if v == "unresolved":
                continue
            w = c.get("witness") or {}
            b_now = (a.get("register") or {}).get("binding")
            if w.get("kind") != "register" or not w.get("as_at") or not w.get("binding") or not b_now:
                res.fail.append(f"{cid}: in_force may be decided only from a point-in-time binding beside the current one")
                continue
            if w["binding"] not in local or b_now not in local:
                res.inc.append(f"{cid}: point-in-time or current section file not local")
                continue
            def _body(path):
                root = safe_xml(open(path, 'rb').read(), os.path.basename(path))
                body = root.find(".//leg:Body", NS)
                return normalise(txt(body if body is not None else root))
            t_then, t_now = _body(local[w["binding"]]), _body(local[b_now])
            want = "holds" if t_then == t_now else "fails"
            if want != v:
                res.fail.append(f"{cid}: point-in-time comparison recomputes as {want}, record says {v}")
            else:
                res.ok.append(f"{cid}: {v} (as at {w['as_at']})")
            continue
        if cid.endswith(".treatment"):
            if v in ("unresolved", "not_applicable"):
                continue
            mentions = (c.get("detail") or {}).get("later_mentions") or []
            missing = [m for m in mentions if m.get("binding") and m["binding"] not in local]
            if missing:
                res.inc.append(f"{cid}: {len(missing)} later judgment file(s) not local")
                continue
            disapproval = ["overruled", "reversed", "set aside", "disapproved", "doubted", "not followed", "wrongly decided",
                           "per incuriam", "departed from", "no longer good law", "should not be followed", "criticised", "criticized"]
            any_dis = False
            bad = None
            for m in mentions:
                if not m.get("binding"):
                    continue
                jt = normalise(parse_judgment(local[m["binding"]])["text"])
                for sent in m.get("sentences") or []:
                    if normalise(sent) not in jt:
                        bad = f"{m.get('cite')}: a recorded sentence is not in the bound judgment"
                    if any(w in sent.lower() for w in disapproval):
                        any_dis = True
            if bad:
                res.fail.append(f"{cid}: {bad}")
                continue
            want = "fails" if any_dis else "holds"
            if want != v:
                res.fail.append(f"{cid}: treatment recomputes as {want}, record says {v}")
            else:
                res.ok.append(f"{cid}: {v} ({len(mentions)} later mentions, sentences verified verbatim)")
            continue
        if cid.endswith(".relevance"):
            if v != "unresolved":
                res.fail.append(f"{cid}: relevance is the lawyer's to decide; the instrument may not assert it, yet the verdict is {v}")
                continue
            # channel support, when recorded, is a reading the lawyer reviews; its grounding is recomputable
            cs = (c.get("detail") or {}).get("channel_support") or {}
            if cs.get("grounding"):
                j, why = judgment_for(aid)
                if j is None:
                    res.inc.append(f"{cid}: {why}")
                    continue
                n = cs.get("grounding_paragraph")
                pt = j["paras"].get(n)
                if pt is None:
                    res.fail.append(f"{cid}: grounding paragraph {n} is not in the bound judgment")
                    continue
                bad = [q for q in cs["grounding"] if len(normalise(q).split()) < 8 or not in_order(segments(q), normalise(pt))]
                if bad:
                    res.fail.append(f"{cid}: a channel's grounding quotation is not verbatim in paragraph {n}: {bad[0][:60]!r}")
                else:
                    res.ok.append(f"{cid}: unresolved (professional layer); channel grounding verified verbatim in paragraph {n}")
            else:
                res.ok.append(f"{cid}: unresolved, as it must be (professional layer)")
            continue
        if kind == "neutral":
            if cid.endswith(".register"):
                if v == "holds":
                    j, why = judgment_for(aid)
                    if j is None:
                        res.inc.append(f"{cid}: {why}")
                        continue
                    if normalise(j["cite"] or "") != normalise(a["canonical"]) and normalise(j["cite"] or "") != normalise(a["as_cited"]):
                        res.fail.append(f"{cid}: bound XML carries citation {j['cite']!r}, not {a['canonical']!r}")
                    elif (a.get("register") or {}).get("content_hash") and j["hash"] != a["register"]["content_hash"]:
                        res.fail.append(f"{cid}: XML content hash {j['hash'][:12]} differs from the record's {a['register']['content_hash'][:12]}")
                    else:
                        res.ok.append(f"{cid}: register holds {j['cite']}")
                elif v == "fails":
                    can = (c.get("witness") or {}).get("canary") or {}
                    obs = (c.get("detail") or {}).get("observations") or []
                    if not can.get("live"):
                        res.fail.append(f"{cid}: absent verdict without a live canary for the family")
                    elif can.get("resolved"):
                        # the register answered positively about this number under
                        # another division: that answer is the liveness witness
                        res.ok.append(f"{cid}: absent as cited; register resolved {', '.join(can['resolved'])}")
                    elif len(obs) < 2:
                        res.fail.append(f"{cid}: absent verdict with fewer than two register observations")
                    else:
                        res.ok.append(f"{cid}: absent verdict carries {len(obs)} observations and canary {can.get('canary')}")
            elif ".name" in cid:
                j, why = judgment_for(aid)
                if j is None:
                    res.inc.append(f"{cid}: {why}")
                    continue
                given = (c.get("detail") or {}).get("given") or a.get("name_given") or ""
                m = re.search(r"The name given in the document, '(.*)', matches the register's name", c["statement"], re.S)
                if m and m.group(1) != given:
                    res.fail.append(f"{cid}: statement names '{m.group(1)}' but detail carries '{given}'")
                    continue
                want = compare_names(given, j["name"] or "")["verdict"]
                if want != v:
                    res.fail.append(f"{cid}: name comparison recomputes as {want}, record says {v}")
                else:
                    res.ok.append(f"{cid}: {v}")
            elif ".pin." in cid:
                j, why = judgment_for(aid)
                if j is None:
                    res.inc.append(f"{cid}: {why}")
                    continue
                n = int(cid.split(".")[-1])
                if not j["paras"]:
                    want = "unresolved"
                else:
                    want = "holds" if n in j["paras"] else "fails"
                if want != v:
                    res.fail.append(f"{cid}: paragraph {n} recomputes as {want}, record says {v}")
                else:
                    res.ok.append(f"{cid}: {v}")
            elif ".quote." in cid:
                j, why = judgment_for(aid)
                if j is None:
                    res.inc.append(f"{cid}: {why}")
                    continue
                d = c.get("detail") or {}
                m = re.search(r"The quotation '(.*)' appears verbatim", c["statement"], re.S)
                if not m:
                    res.inc.append(f"{cid}: cannot read the quotation from the statement")
                    continue
                q = m.group(1)
                truncated = q.endswith("...")
                status, where = quote_status(j, q[:-3] if truncated else q, d.get("pinpoint_given"))
                if v == "holds":
                    ok = status == "verbatim"
                elif v == "fails":
                    ok = status != "verbatim"
                else:
                    ok = d.get("attachment") in ("inferred", "short-form")
                if not ok:
                    res.fail.append(f"{cid}: quotation recomputes as {status} (para {where}), record says {v}")
                else:
                    res.ok.append(f"{cid}: {v} ({status})")
        elif kind in ("statute", "act", "si"):
            b = (a.get("register") or {}).get("binding")
            if cid.endswith(".register"):
                if v == "holds" and b:
                    if b not in local:
                        res.inc.append(f"{cid}: register file not local: {b}")
                        continue
                    root = safe_xml(open(local[b], 'rb').read(), os.path.basename(local[b]))
                    p1 = root.find(".//leg:P1/leg:Pnumber", NS)
                    res.ok.append(f"{cid}: section file present" + (f" (s {p1.text.strip()})" if p1 is not None and p1.text else ""))
                elif v == "holds":
                    res.inc.append(f"{cid}: act-level claim carries no section binding; not recomputed")
            elif cid.endswith(".subsection"):
                if b not in local:
                    res.inc.append(f"{cid}: register file not local: {b}")
                    continue
                root = ET.parse(local[b]).getroot()
                subs = []
                for p2 in root.findall(".//leg:P2", NS):
                    mm = re.search(r"-(\d{1,2}[A-Z]?)$", p2.attrib.get("id", ""))
                    if mm:
                        subs.append(mm.group(1))
                    else:
                        pn = p2.find("leg:Pnumber", NS)
                        if pn is not None and pn.text:
                            subs.append(pn.text.strip().strip("()"))
                m = re.search(r"Subsection \((\d{1,2}[A-Z]?)\)", c["statement"])
                if not m:
                    res.inc.append(f"{cid}: cannot read the subsection from the statement")
                    continue
                want = "holds" if m.group(1) in subs else "fails"
                if want != v:
                    res.fail.append(f"{cid}: subsection recomputes as {want}, record says {v}")
                else:
                    res.ok.append(f"{cid}: {v}")
    # 9 honesty
    if not (rec.get("envelope") or {}).get("out_of_scope"):
        res.fail.append("envelope declares nothing out of scope")
    return res, rec


ALLOWED = re.compile(r"^https://(caselaw\.nationalarchives\.gov\.uk|www\.legislation\.gov\.uk)/")


def refetch(rec, res):
    """The trust root of a bundle is the recipient's own copy of the register
    files. Anyone can forge a file and its digest; nobody can forge what the
    register serves today. Fetch each binding's URL and compare."""
    import urllib.request
    for b in rec.get("source_bindings") or []:
        if b.get("kind") != "register" or not b.get("url"):
            continue
        if not ALLOWED.match(b["url"]):
            res.fail.append(f"refetch: binding {b['path']} points outside the registers: {b['url'][:60]}")
            continue
        try:
            with urllib.request.urlopen(urllib.request.Request(b["url"], headers={"User-Agent": "arcifact-verify/1"}), timeout=40) as r:
                body = r.read(60 * 1024 * 1024)
        except Exception as e:
            res.inc.append(f"refetch: {b['path']} could not be fetched ({type(e).__name__})")
            continue
        got = hashlib.sha256(body).hexdigest()
        if got == b["sha256"]:
            res.ok.append(f"refetch: {b['path']} matches the register today")
        else:
            res.fail.append(f"refetch: {b['path']} differs from what the register serves today ({got[:12]} vs {b['sha256'][:12]}); the judgment changed, or the copy is not the register's")


# ---- OpenTimestamps: copied verbatim from authority/ots.py (parse, serialise, verify against Bitcoin headers)
MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
OP_SHA256, OP_RIPEMD160, OP_SHA1, OP_KECCAK256 = 0x08, 0x03, 0x02, 0x67
OP_APPEND, OP_PREPEND, OP_REVERSE, OP_HEXLIFY = 0xF0, 0xF1, 0xF2, 0xF3
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
DIGEST_LEN = {OP_SHA256: 32, OP_RIPEMD160: 20, OP_SHA1: 20, OP_KECCAK256: 32}
MAX_ARG = 4096


class ProofError(ValueError):
    pass


# ------------------------------------------------------------------ byte streams
class _Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def bytes(self, n):
        if self.i + n > len(self.b):
            raise ProofError("proof truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def byte(self):
        return self.bytes(1)[0]

    def varuint(self):
        v, shift = 0, 0
        while True:
            b = self.byte()
            v |= (b & 0x7F) << shift
            if not b & 0x80:
                return v
            shift += 7
            if shift > 63:
                raise ProofError("varuint too long")

    def varbytes(self, maxlen=MAX_ARG):
        n = self.varuint()
        if n > maxlen:
            raise ProofError("varbytes too long")
        return self.bytes(n)

    def done(self):
        return self.i >= len(self.b)


def _varuint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def _varbytes(b):
    return _varuint(len(b)) + b


# ------------------------------------------------------------------ operations
def _apply(op, msg):
    tag, arg = op
    if tag == OP_SHA256:
        return hashlib.sha256(msg).digest()
    if tag == OP_RIPEMD160:
        return hashlib.new("ripemd160", msg).digest()
    if tag == OP_SHA1:
        return hashlib.sha1(msg).digest()
    if tag == OP_KECCAK256:
        raise ProofError("keccak256 not supported by this verifier")
    if tag == OP_APPEND:
        return msg + arg
    if tag == OP_PREPEND:
        return arg + msg
    if tag == OP_REVERSE:
        return msg[::-1]
    if tag == OP_HEXLIFY:
        return msg.hex().encode()
    raise ProofError(f"unknown op 0x{tag:02x}")


def _read_op(r, tag):
    if tag in (OP_APPEND, OP_PREPEND):
        return (tag, r.varbytes())
    if tag in (OP_SHA256, OP_RIPEMD160, OP_SHA1, OP_KECCAK256, OP_REVERSE, OP_HEXLIFY):
        return (tag, b"")
    raise ProofError(f"unknown op tag 0x{tag:02x}")


def _write_op(op):
    tag, arg = op
    return bytes([tag]) + (_varbytes(arg) if tag in (OP_APPEND, OP_PREPEND) else b"")


# ------------------------------------------------------------------ the timestamp tree
class Timestamp:
    """msg, attestations [(kind, payload)], ops {op: Timestamp}."""

    def __init__(self, msg):
        self.msg = msg
        self.attestations = []
        self.ops = {}

    @classmethod
    def read(cls, r, msg):
        self = cls(msg)

        def tag_or_attestation(tag: int):
            if tag == 0x00:
                self.attestations.append(_read_attestation(r))
            else:
                op = _read_op(r, tag)
                self.ops[op] = Timestamp.read(r, _apply(op, msg))
        tag = r.byte()
        while tag == 0xFF:
            tag_or_attestation(r.byte())
            tag = r.byte()
        tag_or_attestation(tag)
        return self

    def write(self):
        if not self.attestations and not self.ops:
            raise ProofError("an empty timestamp cannot be serialised")
        out = b""
        atts = sorted(self.attestations, key=_att_sort_key)
        ops = sorted(self.ops.items(), key=lambda kv: _write_op(kv[0]))
        if len(atts) > 1:
            for a in atts[:-1]:
                out += b"\xff\x00" + _write_attestation(a)
        if not ops:
            out += b"\x00" + _write_attestation(atts[-1])
            return out
        if atts:
            out += b"\xff\x00" + _write_attestation(atts[-1])
        for op, ts in ops[:-1]:
            out += b"\xff" + _write_op(op) + ts.write()
        op, ts = ops[-1]
        out += _write_op(op) + ts.write()
        return out

    def walk(self):
        """Yield (kind, payload, msg) for every attestation in the tree."""
        for a in self.attestations:
            yield a[0], a[1], self.msg
        for ts in self.ops.values():
            yield from ts.walk()

    def pending_nodes(self):
        """Yield (self, attestation) for every pending attestation, for upgrade."""
        for a in self.attestations:
            if a[0] == "pending":
                yield self, a
        for ts in self.ops.values():
            yield from ts.pending_nodes()


def _read_attestation(r):
    tag = r.bytes(8)
    payload = r.varbytes(8192)
    if tag == TAG_PENDING:
        return ("pending", _Reader(payload).varbytes(1000).decode("utf-8", "replace"))
    if tag == TAG_BITCOIN:
        return ("bitcoin", _Reader(payload).varuint())
    return ("unknown:" + tag.hex(), payload)


def _write_attestation(a):
    kind, payload = a
    if kind == "pending":
        return TAG_PENDING + _varbytes(_varbytes(payload.encode()))
    if kind == "bitcoin":
        return TAG_BITCOIN + _varbytes(_varuint(payload))
    return bytes.fromhex(kind.split(":", 1)[1]) + _varbytes(payload)


def _att_sort_key(a: tuple):
    return _write_attestation(a)


# ------------------------------------------------------------------ detached proof files
def parse(data):
    """(digest, Timestamp) from a detached .ots file. Raises ProofError."""
    if not data.startswith(MAGIC):
        raise ProofError("not an OpenTimestamps proof (magic header absent)")
    r = _Reader(data[len(MAGIC):])
    if r.varuint() != 1:
        raise ProofError("unsupported proof version")
    op = r.byte()
    if op not in DIGEST_LEN:
        raise ProofError("unknown file-hash operation")
    digest = r.bytes(DIGEST_LEN[op])
    ts = Timestamp.read(r, digest)
    if not r.done():
        raise ProofError("trailing bytes after the proof")
    if op != OP_SHA256:
        raise ProofError("the proof's file hash is not SHA-256")
    return digest, ts


def build(digest, ts):
    return MAGIC + _varuint(1) + bytes([OP_SHA256]) + digest + ts.write()


# ------------------------------------------------------------------ Bitcoin headers
def header_fields(header_hex):
    raw = bytes.fromhex(header_hex)
    if len(raw) != 80:
        raise ProofError("a Bitcoin block header is 80 bytes")
    h = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    bits = int.from_bytes(raw[72:76], "little")
    exp, mant = bits >> 24, bits & 0xFFFFFF
    target = mant * (1 << (8 * (exp - 3))) if exp > 3 else mant >> (8 * (3 - exp))
    return {"hash": h[::-1].hex(), "merkle_root": raw[36:68], "time": int.from_bytes(raw[68:72], "little"),
            "target": target, "pow_ok": int.from_bytes(h, "little") <= target}


def ots_verify(digest, proof, headers=None):
    """What a proof establishes for a digest.
    headers: {height (int or str): header_hex}. Returns {'state', 'bound', 'pending': [uris],
    'bitcoin': [{'height', 'checked', 'confirmed', 'block_time', 'reason'}], 'reason'}."""
    out = {"state": "invalid", "bound": False, "pending": [], "bitcoin": [], "reason": ""}
    try:
        pdigest, ts = parse(proof)
    except ProofError as e:
        out["reason"] = f"proof does not parse: {e}"
        return out
    if pdigest != digest:
        out["reason"] = "the proof is for a different digest"
        return out
    out["bound"] = True
    out["state"] = "proof_present"
    headers = {str(k): v for k, v in (headers or {}).items()}
    for kind, payload, msg in ts.walk():
        if kind == "pending":
            out["pending"].append(payload)
        elif kind == "bitcoin":
            entry = {"height": payload, "checked": False, "confirmed": False, "block_time": None, "reason": ""}
            hx = headers.get(str(payload))
            if hx:
                try:
                    f = header_fields(hx)
                    entry["checked"] = True
                    if not f["pow_ok"]:
                        entry["reason"] = "the supplied header does not satisfy its own proof of work"
                    elif f["merkle_root"] != msg:
                        entry["reason"] = "the attested value is not the block's merkle root"
                    else:
                        entry["confirmed"] = True
                        entry["block_time"] = f["time"]
                        entry["block_hash"] = f["hash"]
                except (ProofError, ValueError) as e:
                    entry["reason"] = str(e)
            else:
                entry["reason"] = "no header for this height was supplied"
            out["bitcoin"].append(entry)
    if any(b["confirmed"] for b in out["bitcoin"]):
        out["state"] = "confirmed"
        out["block_time"] = min(b["block_time"] for b in out["bitcoin"] if b["confirmed"])
        out["block_height"] = min(b["height"] for b in out["bitcoin"] if b["confirmed"])
    elif out["bitcoin"]:
        out["state"] = "proof_present"
        out["reason"] = "Bitcoin attestation present but not checked against a header: " + "; ".join(b["reason"] for b in out["bitcoin"])
    elif out["pending"]:
        out["state"] = "pending"
    return out




def check_anchor(rec, res, sources, headers=None):
    """What the anchor establishes, from the proof bytes and a block header, never from the record's own fields.
    Returns one of: none, invalid, proof_present, pending, confirmed (with the block time)."""
    anc = rec.get("anchor")
    if not anc:
        return {"state": "none", "text": "none"}
    body = {k: v for k, v in rec.items() if k != "anchor"}
    digest_hex = hashlib.sha256(canon(body)).hexdigest()
    if digest_hex != str(anc.get("sha256", "")).lower():
        res.fail.append("anchor: its digest is not the digest of the record it sits in")
        return {"state": "invalid", "text": "invalid (digest mismatch)"}
    digest = bytes.fromhex(digest_hex)
    hdrs = dict(headers or {})
    hp = os.path.join(sources, "bitcoin-headers.json")
    if os.path.exists(hp):
        try:
            for k, val in (json.load(open(hp)).get("headers") or {}).items():
                hx = val["header"] if isinstance(val, dict) else val
                if header_fields(hx)["pow_ok"]:
                    hdrs.setdefault(str(k), hx)
                else:
                    res.fail.append(f"anchor: bundled header for block {k} fails its proof of work")
        except (ValueError, KeyError, ProofError) as e:
            res.fail.append(f"anchor: bitcoin-headers.json unreadable: {e}")
    best = {"state": "none"}
    n_present = 0
    rank = {"proof_present": 1, "pending": 2, "confirmed": 3}
    for o in anc.get("ots") or []:
        p = o.get("proof")
        if not p or not os.path.exists(os.path.join(sources, p)):
            continue
        data = open(os.path.join(sources, p), "rb").read()
        r = ots_verify(digest, data, hdrs)
        if r["state"] == "invalid":
            res.fail.append(f"anchor: {p}: {r['reason']}")
            return {"state": "invalid", "text": f"invalid ({p}: {r['reason']})"}
        n_present += 1
        if rank.get(r["state"], 0) > rank.get(best["state"], 0):
            best = dict(r, proof=p)
    if not n_present:
        res.inc.append("anchor: no proof file beside the record; the digest matches but nothing external can be checked")
        return {"state": "none", "text": "digest matches, no proof file present"}
    if best["state"] == "confirmed":
        t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(best["block_time"]))
        res.ok.append(f"anchor: {best['proof']} confirmed in Bitcoin block {best['block_height']} at {t} (merkle root equal; header proof of work checked)")
        return {"state": "confirmed", "text": f"confirmed: Bitcoin block {best['block_height']} at {t}", "block_time": best["block_time"], "block_height": best["block_height"]}
    if best["state"] == "pending":
        res.ok.append(f"anchor: {best['proof']} parses and is bound to the record; calendar promise only ({', '.join(best['pending'])}); not yet in Bitcoin")
        return {"state": "pending", "text": "pending (calendar promise; run `authority anchor --upgrade` later)"}
    res.ok.append(f"anchor: {best['proof']} parses and is bound to the record; {best.get('reason') or 'no attestation checked'}")
    return {"state": "proof_present", "text": "proof present, attestation not checked (" + (best.get("reason") or "") + ")"}


def check_signature(rec, res, issuer_keys):
    """Level 3. issuer_keys: {key_id: public_key_hex}."""
    sig = rec.get("signature")
    if not sig:
        return "none"
    if not issuer_keys:
        return "present, not checked (give --issuer-key or --keys)"
    pub = issuer_keys.get(sig.get("key_id"))
    if not pub and str(sig.get("public_key", "")).lower() in issuer_keys.values():
        pub = str(sig.get("public_key")).lower()
    if not pub:
        res.fail.append(f"signature: key {sig.get('key_id')} is not a listed issuer key")
        return "invalid"
    if pub.lower() != str(sig.get("public_key", "")).lower():
        res.fail.append("signature: embedded public key differs from the listed key")
        return "invalid"
    body = {k: v for k, v in rec.items() if k not in ("signature", "anchor")}
    if not ed25519_verify(bytes.fromhex(pub), canon(body), bytes.fromhex(str(sig.get("sig", "")))):
        res.fail.append("signature: does not verify over the sealed record")
        return "invalid"
    res.ok.append(f"signature: valid, key {sig.get('key_id')}, signed {sig.get('signed_at')}")
    return f"valid ({sig.get('key_id')})"


# ---- Ed25519 verification, pure Python (RFC 8032), so this file stays standard-library only
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)


def _add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    dd = z1 * 2 * z2 % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(P, e):
    Q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        e >>= 1
    return Q


def _enc(P):
    x, y, z, t = P
    zi = _inv(z)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _dec(s):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _xrecover(y)
    if x & 1 != sign:
        x = _P - x
    P = (x, y, 1, (x * y) % _P)
    if not (P[2] % _P != 0 and P[0] * P[1] % _P == P[2] * P[3] % _P and (P[1] * P[1] - P[0] * P[0] - P[2] * P[2] - _D * P[3] * P[3]) % _P == 0):
        raise ValueError("not on curve")
    return P


def ed25519_public_key_ok(public):
    """Canonical encoding (y below the field prime) and not a small-order point."""
    if len(public) != 32:
        return False
    y = int.from_bytes(public, "little") & ((1 << 255) - 1)
    if y >= _P:
        return False
    try:
        A = _dec(public)
    except (ValueError, ZeroDivisionError):
        return False
    return _enc(_mul(A, 8)) != _enc((0, 1, 1, 0))


def ed25519_verify(public, msg, sig):
    if len(sig) != 64 or len(public) != 32 or not ed25519_public_key_ok(public):
        return False
    try:
        A = _dec(public)
        R = _dec(sig[:32])
    except (ValueError, ZeroDivisionError):
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _L
    return _enc(_mul(_B, s)) == _enc(_add(R, _mul(A, k)))


def _headers_arg(a):
    out = {}
    if getattr(a, "bitcoin_headers", None):
        d = json.load(open(a.bitcoin_headers))
        for k, val in (d.get("headers") or d).items():
            out[str(k)] = val["header"] if isinstance(val, dict) else val
    if getattr(a, "bitcoin_api", None) and getattr(a, "_rec", None):
        for o in (a._rec.get("anchor") or {}).get("ots") or []:
            p = os.path.join(a.sources, o.get("proof") or "")
            if not os.path.exists(p):
                continue
            try:
                _, ts = parse(open(p, "rb").read())
                for kind, payload, _m in ts.walk():
                    if kind == "bitcoin" and str(payload) not in out:
                        hdr = {"User-Agent": "arcifact-authority-verifier"}
                        bh = urllib.request.urlopen(urllib.request.Request(f"{a.bitcoin_api}/block-height/{payload}", headers=hdr), timeout=30).read().decode().strip()
                        hx = urllib.request.urlopen(urllib.request.Request(f"{a.bitcoin_api}/block/{bh}/header", headers=hdr), timeout=30).read().decode().strip()
                        f = header_fields(hx)
                        if f["pow_ok"] and f["hash"] == bh:
                            out[str(payload)] = hx
            except (ProofError, ValueError, OSError):
                pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("record")
    ap.add_argument("--sources", required=True)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--refetch", action="store_true", help="level 2: fetch every register binding from its recorded URL and compare digests")
    ap.add_argument("--issuer-key", default=None, help="level 3: an issuer public key (hex), or KEY_ID=HEX")
    ap.add_argument("--keys", default=None, help="level 3: a JSON file {key_id: public_key_hex}, such as the published issuer registry")
    ap.add_argument("--bitcoin-headers", default=None, help="a JSON file {height: header_hex} for the anchor's Bitcoin attestations (bitcoin-headers.json beside the record is read automatically, after a proof-of-work check)")
    ap.add_argument("--bitcoin-api", default=None, help="fetch block headers from this explorer API base (for example https://blockstream.info/api); network")
    a = ap.parse_args()
    res, rec = verify(a.record, a.sources)
    a._rec = rec
    keys = {}
    if a.keys:
        keys.update({k: str(v).lower() for k, v in json.load(open(a.keys)).items()})
    if a.issuer_key:
        kid, _, hexk = a.issuer_key.partition("=")
        keys[kid if hexk else "given"] = (hexk or kid).lower()
    refetched = False
    if a.refetch and rec:
        refetch(rec, res)
        refetched = True
    sig_status = check_signature(rec, res, keys) if rec else "none"
    anchor = check_anchor(rec, res, a.sources, headers=_headers_arg(a)) if rec else {"state": "none", "text": "none"}
    anchor_status = anchor["text"]
    if not a.quiet:
        for m in res.ok:
            print(f"  ok            {m}")
        for m in res.inc:
            print(f"  not checked   {m}")
        for m in res.fail:
            print(f"  FAILED        {m}")
    if res.fail:
        verdict = "INVALID"
    elif res.inc:
        verdict = "INCOMPLETE"
    else:
        verdict = "SELF_CONSISTENT"
        if refetched:
            verdict = "REGISTER_CORROBORATED"
        if sig_status.startswith("valid"):
            verdict = "SIGNED+REGISTER_CORROBORATED" if refetched else "SIGNED"
            if anchor["state"] == "confirmed":
                verdict = verdict.replace("SIGNED", "SIGNED+TIMESTAMP_CONFIRMED", 1)
            elif anchor["state"] == "pending":
                verdict = verdict.replace("SIGNED", "SIGNED+ANCHOR_PENDING", 1)
            elif anchor["state"] == "proof_present":
                verdict = verdict.replace("SIGNED", "SIGNED+ANCHOR_PROOF_PRESENT", 1)
    print(f"VERDICT  {verdict}   ({len(res.ok)} checks recomputed, {len(res.inc)} not checked, {len(res.fail)} failed)")
    print(f"LEVELS   1 self-consistency: {'established' if not res.fail else 'failed'}; "
          f"2 register corroboration: {('established' if not any(f.startswith('refetch') for f in res.fail) else 'failed') if refetched else 'not requested (--refetch)'}; "
          f"3 signature: {sig_status}; timestamp anchor: {anchor_status}")
    return 1 if res.fail else (2 if res.inc else 0)


if __name__ == "__main__":
    sys.exit(main())
