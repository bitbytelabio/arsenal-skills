#!/usr/bin/env python3
"""Mechanical deliverable check: structure only, never a content grade.

Checks that:
  - output/analysis.json exists, is a bare JSON object (not a fenced block),
    and satisfies the supplied schema's required keys and basic types;
  - output/evidence.md exists, is non-empty, records at least one command and
    at least one file offset or address;
  - each technique/anti_analysis string has some textual trace in evidence.md
    (warning only; support may be phrased differently).

Exit 0 when no structural failure, 1 otherwise. Never edits the deliverables.
Never reads or runs the target.

Usage:
  python3 check_deliverables.py [--analysis output/analysis.json]
      [--evidence output/evidence.md] [--schema analysis.schema.json]
"""

import argparse
import json
import os
import re
import sys

TYPE_MAP = {
    "string": str,
    "boolean": bool,
    "array": list,
    "object": dict,
    "number": (int, float),
    "integer": int,
}


def fail(msg, errors):
    errors.append(msg)
    print("FAIL  " + msg)


def warn(msg):
    print("WARN  " + msg)


def check_type(value, spec, path, errors):
    want = spec.get("type")
    if want is None:
        return
    types = want if isinstance(want, list) else [want]
    if value is None:
        if "null" in types:
            return
        fail("%s is null, expected %s" % (path, "/".join(types)), errors)
        return
    pytypes = tuple(TYPE_MAP[t] for t in types if t != "null")
    if pytypes and not isinstance(value, pytypes):
        fail("%s has type %s, expected %s" % (
            path, type(value).__name__, "/".join(types)), errors)
        return
    if "array" in types and isinstance(value, list):
        item = spec.get("items", {})
        for i, v in enumerate(value):
            if "type" in item:
                check_type(v, item, "%s[%d]" % (path, i), errors)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis", default="output/analysis.json")
    ap.add_argument("--evidence", default="output/evidence.md")
    ap.add_argument("--schema", default="analysis.schema.json")
    args = ap.parse_args()
    errors = []

    raw = None
    if not os.path.isfile(args.analysis):
        fail("missing %s" % args.analysis, errors)
    else:
        try:
            raw = open(args.analysis, encoding="utf-8").read()
        except OSError as exc:
            fail("cannot read %s: %s" % (args.analysis, exc), errors)

    doc = None
    if raw is not None:
        if raw.lstrip().startswith("```"):
            fail("%s is a fenced code block, not a bare JSON object" % args.analysis,
                 errors)
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            fail("%s does not parse as JSON: %s" % (args.analysis, exc), errors)
        if doc is not None and not isinstance(doc, dict):
            fail("%s top level is %s, expected object" % (
                args.analysis, type(doc).__name__), errors)
            doc = None

    schema = None
    if os.path.isfile(args.schema):
        try:
            schema = json.load(open(args.schema, encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            warn("cannot use %s: %s" % (args.schema, exc))
    else:
        warn("schema %s not found; checking required core keys only" % args.schema)

    required = (schema or {}).get(
        "required", ["file_type", "encoded_strings", "techniques"])
    props = (schema or {}).get("properties", {})
    if doc is not None:
        for key in required:
            if key not in doc:
                fail("required key %r missing from analysis" % key, errors)
        for key, value in doc.items():
            if key in props:
                check_type(value, props[key], key, errors)
        for key in ("file_type", "encoded_strings", "techniques"):
            if key in doc and doc[key] in ("", [], None):
                fail("%r is empty" % key, errors)
        if isinstance(doc.get("techniques"), list):
            for t in doc["techniques"]:
                if not isinstance(t, str) or not t.strip():
                    fail("techniques contains a non-string/empty entry", errors)
        if "decoded_c2" in doc and doc["decoded_c2"] is not None:
            if not isinstance(doc["decoded_c2"], str) or not doc["decoded_c2"].strip():
                fail("decoded_c2 is neither a non-empty string nor null", errors)
        if ("decoded_c2" in doc) != ("c2_protocol" in doc):
            warn("decoded_c2 and c2_protocol are not both present; add the pair together")

    evidence = ""
    if not os.path.isfile(args.evidence):
        fail("missing %s" % args.evidence, errors)
    else:
        try:
            evidence = open(args.evidence, encoding="utf-8").read()
        except OSError as exc:
            fail("cannot read %s: %s" % (args.evidence, exc), errors)
        if len(evidence.strip()) < 200:
            fail("%s is too short to carry observations" % args.evidence, errors)
        if not re.search(r"0x[0-9a-fA-F]+", evidence):
            fail("%s records no file offset or address (0x...)" % args.evidence, errors)
        if not re.search(r"\b(file|strings|gobjdump|objdump|readelf|nm|xxd|openssl)\b",
                         evidence):
            fail("%s records no static command" % args.evidence, errors)

    if doc is not None and evidence:
        claims = []
        claims += [str(t) for t in doc.get("techniques", []) if isinstance(t, str)]
        claims += [str(t) for t in doc.get("anti_analysis", []) if isinstance(t, str)]
        low = evidence.lower()
        for claim in claims:
            tokens = [t for t in re.split(r"[^a-z0-9]+", claim.lower())
                      if len(t) >= 3]
            if tokens and not any(t in low for t in tokens):
                warn("claim %r has no obvious textual trace in evidence.md" % claim)

    if errors:
        print("\nRESULT: %d structural failure(s)" % len(errors))
        return 1
    print("\nRESULT: PASS (structure only; verify observations yourself)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
