import csv
import json
from pathlib import Path

import pytest

from fwa import early_stop, oracle_manager
from fwa.analyzers import oast_interaction
from fwa.fuzzer import Request
from fwa.utils import payloads, webserver

ROOT = Path(__file__).resolve().parents[1]


def rows():
    with (ROOT / "payloads.csv").open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_every_payload_type_is_judged_by_one_rule():
    for payload_type in {row["Type"] for row in rows()}:
        rules = [r for r in oracle_manager.get_rules(oracle_manager.get_default_oracle_path())
                 if payload_type in oracle_manager.payload_types(r)]
        assert len(rules) == 1, (payload_type, rules)


def test_simple_first_orders_by_tier_then_level_then_file_order():
    file_rows = [{"Payload": "a", "Type": "SQL_TIME_BASED", "Level": "1"}, {"Payload": "b", "Type": "SQL", "Level": "2"},
                 {"Payload": "c", "Type": "CMDI_OAST", "Level": "1"}, {"Payload": "d", "Type": "XSS", "Level": "1"},
                 {"Payload": "e", "Type": "SQL", "Level": "1"}, {"Payload": "f", "Type": "CMDI_TIME_BASED", "Level": "1"}]
    assert [r["Payload"] for r in payloads.simple_first(file_rows)] == ["d", "e", "b", "a", "f", "c"]
    with pytest.raises(ValueError, match="Level"):
        payloads.simple_first([{"Payload": "x", "Type": "SQL"}])


def test_every_payload_has_a_level_and_simple_first_keeps_the_rows():
    ordered = payloads.simple_first(rows())
    assert sorted(map(tuple, (r.values() for r in ordered))) == sorted(map(tuple, (r.values() for r in rows())))
    keys = [(payloads.tier(r["Type"]), payloads.level(r)) for r in ordered]
    assert keys == sorted(keys)


BASE_TEXT = "<html><body>result</body></html>"


def har_entry(value, text):
    return {"time": 10,
            "request": {"method": "GET", "url": "http://target.test/item?q=" + value, "cookies": [], "headers": [],
                        "queryString": [{"name": "q", "value": value}]},
            "response": {"status": 200, "headers": [], "content": {"size": len(text), "text": text}}}


def test_a_detection_stops_only_its_rule_at_the_injection_point(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("FWA_OAST_INTERACTIONS", raising=False)
    monkeypatch.setattr(oast_interaction, "_interacted", None)
    monkeypatch.setattr(webserver, "start_webserver", lambda: None)
    monkeypatch.setattr(webserver, "stop_webserver", lambda: None)
    payload_rows = [{"Payload": "'", "Type": "SQL"}, {"Payload": "1 OR 1=1", "Type": "SQL"},
                    {"Payload": "<h1>fwa-htmli</h1>", "Type": "HTMLI"},
                    {"Payload": "1 AND SLEEP(5)", "Type": "SQL_TIME_BASED"}]
    base = Request("http://target.test/item?q=1", "GET", [], [])
    base.har_index = 0
    fuzz_reqs = base.get_fuzz_reqs("query_params", payloads.payloads(payload_rows), "q")
    entries_file = tmp_path / "entries.jsonl"
    entries_file.touch()
    sent = []

    def send(req):
        """The recording proxy: the target answers with an SQL error to a quote and reflects the rest."""
        sent.append(req.fuzz_payload)
        text = "You have an error in your SQL syntax" if req.fuzz_payload == "'" else req.fuzz_payload
        with entries_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(har_entry(req.fuzz_payload, text)) + "\n")
        return object()

    report = early_stop.fuzz(fuzz_reqs, [har_entry("1", BASE_TEXT)], payload_rows, str(entries_file), send, lambda done: None)

    assert sent == ["'", "<h1>fwa-htmli</h1>"]
    assert [(s.rule, s.payload, s.point.parameter) for s in report.stops] == [("sql", "'", "q"), ("html_injection", "<h1>fwa-htmli</h1>", "q")]
    assert [(s.rule, s.payload, s.payload_type) for s in report.skipped] == [("sql", "1 OR 1=1", "SQL"),
                                                                            ("sql", "1 AND SLEEP(5)", "SQL_TIME_BASED")]
    assert report.to_json()["stops"][0] == {"request_index": 0, "location": "query_params", "parameter": "q",
                                            "injected": "value", "rule": "sql", "payload": "'", "payload_type": "SQL"}


def test_an_unrecorded_response_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(webserver, "start_webserver", lambda: None)
    monkeypatch.setattr(webserver, "stop_webserver", lambda: None)
    payload_rows = [{"Payload": "'", "Type": "SQL"}]
    base = Request("http://target.test/item?q=1", "GET", [], [])
    base.har_index = 0
    entries_file = tmp_path / "entries.jsonl"
    entries_file.touch()
    with pytest.raises(early_stop.EarlyStopError, match="0 recorded entries for one response"):
        early_stop.fuzz(base.get_fuzz_reqs("query_params", ["'"], "q"), [har_entry("1", BASE_TEXT)], payload_rows,
                       str(entries_file), lambda req: object(), lambda done: None)
