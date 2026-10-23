#!/usr/bin/env python3
"""Run tests/pipeline_cases.json through Graylog's pipeline simulator (stdlib only).

  python3 tests/run_pipeline_tests.py            # all cases
  python3 tests/run_pipeline_tests.py ipv6 dhcp  # only cases whose name contains any of the words
  python3 tests/run_pipeline_tests.py -v         # also print every field of the simulated message

Env: GRAYLOG_URL (http://localhost:9000), GRAYLOG_USER (admin), GRAYLOG_PASSWORD (admin).
Exit code 1 if any case fails.

Case format (see pipeline_cases.json):
  name         unique label
  raw          full RFC5424 syslog line  OR  message (+ application_name, source, timestamp)
  expect       {field: value}   subset match; numbers/bools compare by value, "*" = field must exist
  absent       [field, ...]     fields that must NOT be set
"""
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

URL = os.getenv("GRAYLOG_URL", "http://localhost:9000").rstrip("/")
AUTH = base64.b64encode(
    f"{os.getenv('GRAYLOG_USER', 'admin')}:{os.getenv('GRAYLOG_PASSWORD', 'admin')}".encode()).decode()
DEFAULT_STREAM = "000000000000000000000001"  # the pipeline is connected to the Default Stream
CASES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pipeline_cases.json")
DEFAULTS = {"source": "opnsense.poc.local", "application_name": "filterlog",
            "timestamp": "2026-10-23T10:00:00.000Z"}

RFC5424 = re.compile(r"^<\d+>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) \S+ \S+ (?:-|(?:\[[^\]]*\])+) ?(?P<msg>.*)$", re.S)


def build_message(case, n):
    msg = dict(DEFAULTS)
    if "raw" in case:
        m = RFC5424.match(case["raw"].strip())
        if not m:
            raise ValueError("raw is not RFC5424: <pri>1 TS HOST APP PID MSGID SD MSG")
        # Graylog renders a DateTime as ISO-8601 with exactly 3 fractional digits; mimic that
        ts = re.sub(r"(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$",
                    lambda t: "." + ((t[1] or "") + "000")[:3] + t[2], m["ts"])
        msg.update(source=m["host"], application_name=m["app"], message=m["msg"], timestamp=ts)
    else:
        msg["message"] = case["message"]
        for k in ("source", "application_name", "timestamp"):
            if k in case:
                msg[k] = case[k]
    msg["_id"] = f"test-{n}"
    return msg


def simulate(msg):
    body = json.dumps({"stream_id": DEFAULT_STREAM, "message": msg}).encode()
    req = urllib.request.Request(f"{URL}/api/system/pipelines/simulate", data=body, method="POST", headers={
        "Authorization": f"Basic {AUTH}", "Content-Type": "application/json", "X-Requested-By": "pipeline-tests"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["messages"][0]["message"]


def same(actual, expected):
    if expected == "*":
        return True
    if isinstance(expected, bool) or isinstance(actual, bool):
        return str(actual).lower() == str(expected).lower()
    return actual == expected or str(actual) == str(expected)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbose = "-v" in sys.argv
    cases = json.load(open(CASES_FILE, encoding="utf-8"))["cases"]
    names = [c["name"] for c in cases]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        sys.exit(f"duplicate case names: {sorted(dup)}")
    if args:
        cases = [c for c in cases if any(a in c["name"] for a in args)]
    passed = failed = 0
    for i, case in enumerate(cases):
        problems = []
        try:
            out = simulate(build_message(case, i))
        except (urllib.error.URLError, ValueError, KeyError) as e:
            out, problems = {}, [f"error: {e}"]
        for k, want in case.get("expect", {}).items():
            if k not in out:
                problems.append(f"  {k}: expected {want!r}, field missing")
            elif not same(out[k], want):
                problems.append(f"  {k}: expected {want!r}, got {out[k]!r}")
        for k in case.get("absent", []):
            if k in out:
                problems.append(f"  {k}: expected absent, got {out[k]!r}")
        if problems:
            failed += 1
            print(f"FAIL  {case['name']}")
            print("\n".join(problems))
        else:
            passed += 1
            print(f"PASS  {case['name']}")
        if verbose:
            print("      " + json.dumps(out, sort_keys=True, ensure_ascii=False))
    print(f"\n{passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
