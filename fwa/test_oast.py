import importlib
import json
import sys
from pathlib import Path

from fwa.oracle import cmdi, ssrf

DOMAIN = "cn7v2k0h4r8s6q1m3p5xabcdefghijklm.oast.lab"


def fresh_analyzer(monkeypatch, path):
    if path is None:
        monkeypatch.delenv("FWA_OAST_INTERACTIONS", raising=False)
    else:
        monkeypatch.setenv("FWA_OAST_INTERACTIONS", str(path))
    from fwa.analyzers import oast_interaction
    return importlib.reload(oast_interaction)


def entry(value):
    return {"payload": {"name": "url", "value": value, "type": "SSRF_OAST"}}


def test_payload_whose_domain_was_contacted_has_an_interaction(tmp_path, monkeypatch):
    interactions = tmp_path / "oast-interactions.jsonl"
    interactions.write_text(json.dumps({"protocol": "dns", "unique-id": DOMAIN.split(".")[0],
                                        "full-id": DOMAIN.split(".")[0]}) + "\n", encoding="utf-8")
    analyzer = fresh_analyzer(monkeypatch, interactions)
    assert analyzer.analyze({}, entry(f"http://{DOMAIN}/")) == {"oast_interaction": True}
    assert analyzer.analyze({}, entry("http://othero7v2k0h4r8s6q1m3p5xabcdef.oast.lab/")) == {"oast_interaction": False}


def test_without_a_configured_channel_no_payload_has_an_interaction(monkeypatch):
    assert fresh_analyzer(monkeypatch, None).analyze({}, entry(f"http://{DOMAIN}/")) == {"oast_interaction": False}


def test_oast_payload_types_are_detected_by_their_interaction():
    for module, payload_type in ((ssrf, "SSRF_OAST"), (cmdi, "CMDI_OAST")):
        observation = {"payload_type": payload_type, "oast_interaction": "1"}
        assert module.oracle(observation)
        assert not module.oracle({**observation, "oast_interaction": "0"})


def test_each_oast_payload_gets_its_own_domain():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
    from fwa_scan import with_oast_domains
    rows = [{"Payload": "http://{oast}/", "Type": "SSRF_OAST"}, {"Payload": "file:///etc/passwd", "Type": "SSRF"},
            {"Payload": ";ping -c 1 {oast}", "Type": "CMDI_OAST"}]
    assert [row["Payload"] for row in with_oast_domains(rows, ["a.oast.lab", "b.oast.lab"])] == \
        ["http://a.oast.lab/", "file:///etc/passwd", ";ping -c 1 b.oast.lab"]
