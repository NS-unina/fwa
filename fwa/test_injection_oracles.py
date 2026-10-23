import importlib
import json
from pathlib import Path

import pytest

from fwa.analyzers import payload_reflection, redirect, strings_in_response, time_delay
from fwa.analyzers.alert_execution import ALERT_MARKER
from fwa.analyzers.strings_in_response import COMPUTED_MARKER
from fwa.fuzzer import Request
from fwa.oracle import cmdi, code_injection, lfi, open_redirect, sql, ssrf
from fwa.utils import payloads

ROOT = Path(__file__).resolve().parents[1]


def entry(text="", status=200, headers=(), time=10, url="http://target.test/page", payload=None):
    e = {"time": time, "request": {"url": url},
         "response": {"status": status, "headers": [{"name": n, "value": v} for n, v in headers],
                      "content": {"size": len(text), "text": text}}}
    if payload is not None:
        e["payload"] = {"name": "p", "value": payload, "type": "X"}
    return e


def observation(payload_type, valid_text, fuzz_text, **extra):
    """An observation row as oracle_manager reads it back from observations.csv: all strings."""
    valid, fuzz = entry(valid_text), entry(fuzz_text)
    row = {"payload_type": payload_type, "status_code": "200", "status_code_is_different": "False",
           "content_length": "0", "time_delay": "False", "time_delay_ms": "0"}
    row.update({k: str(v) for k, v in strings_in_response.analyze(valid, fuzz).items()})
    row.update({k: str(v) for k, v in extra.items()})
    return row


def test_csv_zero_flags_are_false():
    # "0" read back from the CSV used to be truthy: every LFI payload was reported.
    assert not lfi.oracle(observation("LFI", "page", "page"))
    assert lfi.oracle(observation("LFI", "page", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin"))


def test_sql_error_must_be_introduced_by_the_payload():
    error = "You have an error in your SQL syntax; check the manual"
    assert sql.oracle(observation("SQL", "results", error))
    assert not sql.oracle(observation("SQL", error, error))
    assert sql.oracle(observation("SQL", "ok", "ok", status_code=500, status_code_is_different=True))


def test_time_based_needs_an_absolute_delay():
    assert sql.oracle(observation("SQL_TIME_BASED", "", "", time_delay=True, time_delay_ms=5012))
    assert not sql.oracle(observation("SQL_TIME_BASED", "", "", time_delay=True, time_delay_ms=60))
    assert cmdi.oracle(observation("CMDI_TIME_BASED", "", "", time_delay=True, time_delay_ms=5003))
    assert time_delay.analyze(entry(time=12), entry(time=5100)) == {"time_delay": True, "time_delay_ms": 5088}


def test_computed_marker_is_not_a_reflection():
    assert COMPUTED_MARKER not in "1873*7177"
    assert cmdi.oracle(observation("CMDI", "ping", f"ping\n{COMPUTED_MARKER}\n"))
    assert not cmdi.oracle(observation("CMDI", "ping", "ping ;echo $((1873*7177))"))
    assert code_injection.oracle(observation("CODE_INJECTION", "", COMPUTED_MARKER))
    assert not code_injection.oracle(observation("CODE_INJECTION", COMPUTED_MARKER, COMPUTED_MARKER))


def test_ssrf_local_file():
    assert ssrf.oracle(observation("SSRF", "Could not resolve host", "root:x:0:0:root:/root:/bin/bash"))
    assert not ssrf.oracle(observation("SSRF", "Could not resolve host", "Could not resolve host"))


def test_payload_reflection():
    html = "<h1>fwa-htmli</h1>"
    assert payload_reflection.analyze(entry("hi"), entry(f"<p>{html}</p>", payload=html)) == {"payload_reflected": 1}
    assert payload_reflection.analyze(entry("hi"), entry("&lt;h1&gt;fwa-htmli&lt;/h1&gt;", payload=html)) == {"payload_reflected": 0}
    # Cookie values are recorded URL-encoded.
    assert payload_reflection.analyze(entry(""), entry(html, payload="%3Ch1%3Efwa-htmli%3C/h1%3E")) == {"payload_reflected": 1}


@pytest.mark.parametrize("location, expected", [
    ("https://fwa-redirect.example/", 1),
    ("//fwa-redirect.example/", 1),
    ("https://example.test/", 0),
    ("/local", 0),
])
def test_redirect_to_payload_host(location, expected):
    fuzz = entry(status=302, headers=[("Location", location)], payload="https://fwa-redirect.example/")
    observed = redirect.analyze(entry(), fuzz)
    assert observed == {"redirect_to_payload_host": expected}
    assert open_redirect.oracle({"payload_type": "OPEN_REDIRECT", **{k: str(v) for k, v in observed.items()}}) == bool(expected)
    assert redirect.analyze(entry(), entry(headers=[("Location", location)], payload="https://fwa-redirect.example/")) == {"redirect_to_payload_host": 0}


def test_fuzz_only_the_selected_parameter():
    r = Request("http://target.test/page?a=1&b=2", "GET", [{"name": "c", "value": "3"}],
                [{"name": "Referer", "value": "x"}, {"name": "Host", "value": "target.test"}])
    reqs = r.get_fuzz_reqs("query_params", ["<x>", "'"], "b")
    assert [req.query_params for req in reqs] == [{"a": "1", "b": "%3Cx%3E"}, {"a": "1", "b": "%27"}]
    headers = r.get_fuzz_reqs("headers", ["' OR 1=1"], "Referer")
    assert [req.headers["Referer"] for req in headers] == ["' OR 1=1"]
    assert r.get_fuzz_reqs("cookies", ["'"], "absent") == []


def test_payload_file_covers_every_benchmark_class():
    rows = payloads.load(str(ROOT / "payloads.csv"))
    values = [row["Payload"] for row in rows]
    assert len(values) == len(set(values)), "a payload must map to one type"
    types = {row["Type"] for row in rows}
    classes = json.loads((ROOT / "benchmark" / "classes.json").read_text())["classes"]
    for configuration in classes.values():
        assert set(configuration["payload_types"]) <= types
        assert hasattr(importlib.import_module("fwa.oracle." + configuration["rule"]), "oracle")
    assert all(f"alert({ALERT_MARKER})" in row["Payload"] for row in rows
               if row["Type"] == "XSS" and "alert" in row["Payload"])
    assert all("1873*7177" in row["Payload"] for row in rows
               if row["Type"] == "CODE_INJECTION" or row["Type"] == "CMDI" and "echo" in row["Payload"])
