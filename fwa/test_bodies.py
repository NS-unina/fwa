import json
from pathlib import Path

from fwa.fuzzer import Request
from fwa.utils import har, payloads

ROOT = Path(__file__).resolve().parents[1]
XML = '<?xml version="1.0"?><root><login>bee</login><secret>tester</secret></root>'


def request(url="http://target.test/app/page"):
    return Request(url, "POST", [], [{"name": "Content-Type", "value": "application/json"}])


def fuzz_entry(url, text="", mime_type=""):
    entry = {"request": {"url": url, "queryString": [], "headers": [], "cookies": []}}
    if mime_type:
        entry["request"]["postData"] = {"mimeType": mime_type, "text": text, "params": []}
    return entry


def test_json_value_payloads_and_string_payloads():
    r = request()
    r.set_json_body('{"id":"1","message":"tester"}')
    reqs = r.get_fuzz_reqs("json_body", ['{"$ne":null}', "'"], "id")
    assert [req.json_body for req in reqs] == [{"id": {"$ne": None}, "message": "tester"}, {"id": "'", "message": "tester"}]
    assert r.json_body == {"id": "1", "message": "tester"}
    array = request()
    array.set_json_body('[1, 2]')
    assert array.get_fuzz_reqs("json_body", ["'"], None) == []


def test_xml_leaf_text_is_escaped_and_declaration_kept():
    r = request()
    r.set_xml_body(XML)
    (fuzzed,) = r.get_fuzz_reqs("xml_params", ["<x>'"], "login")
    assert fuzzed.xml_text() == '<?xml version="1.0"?><root><login>&lt;x&gt;\'</login><secret>tester</secret></root>'
    repeated = request()
    repeated.set_xml_body("<root><item>a</item><item>b</item><id>1</id></root>")
    assert repeated.xml_params == {"id": "1"}


def test_path_segment_is_named_by_index_and_encoded():
    r = request("http://target.test/bwapp/bWAPP/xss_php_self.php/tester")
    assert r.path_params["4"] == "tester"
    (fuzzed,) = r.get_fuzz_reqs("path_params", ["<a>/b"], "4")
    assert fuzzed.base_url() == "http://target.test/bwapp/bWAPP/xss_php_self.php/%3Ca%3E%2Fb"
    assert fuzzed.complete_url() == "http://target.test/bwapp/bWAPP/xss_php_self.php/%3Ca%3E%2Fb?"


def test_payloads_are_found_in_json_xml_and_path():
    rows = [{"Payload": '{"$ne":null}', "Type": "NOSQL"}, {"Payload": "'", "Type": "SQL"}, {"Payload": "<a>/b", "Type": "XSS"}]
    found = har.find_payload(fuzz_entry("http://t/x", '{"id":{"$ne":null}}', "application/json"), rows)
    assert found == {"name": "id", "value": '{"$ne":null}', "type": "NOSQL", "location": "json"}
    found = har.find_payload(fuzz_entry("http://t/x", "<root><login>'</login></root>", "application/xml"), rows)
    assert (found["name"], found["type"], found["location"]) == ("login", "SQL", "xml")
    found = har.find_payload(fuzz_entry("http://t/app/%3Ca%3E%2Fb"), rows)
    assert (found["name"], found["type"], found["location"]) == ("2", "XSS", "path")


def test_path_fuzzed_entries_pair_with_their_valid_entry():
    rows = [{"Payload": "<a>/b", "Type": "XSS"}]
    entries = [fuzz_entry("http://t/app/%3Ca%3E%2Fb"), fuzz_entry("http://t/other/%3Ca%3E%2Fb")]
    for entry in entries:
        entry["payload"] = har.find_payload(entry, rows)
    assert har.get_entries_by_url("http://t/app/tester", entries) == entries[:1]


def test_json_valued_payloads_round_trip_unchanged():
    # A JSON-valued payload is recorded as compact JSON; it must equal the payload to be observed.
    for row in payloads.load(str(ROOT / "payloads.csv")):
        try:
            value = json.loads(row["Payload"])
        except ValueError:
            continue
        if isinstance(value, (dict, list)):
            assert json.dumps(value, separators=(",", ":")) == row["Payload"]
