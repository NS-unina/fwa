"""Online oracle of ``fwa fuzz --early-stop``.

The fuzz requests are sent in order, one at a time. fwa's recording proxy
appends each recorded HAR entry to an entries file before the response reaches
the fuzzer (``recorder.py``, option ``entries``), and the entry is analyzed at
once with the analyzers and oracle rules that ``fwa analyze`` and ``fwa oracle``
run afterwards on the same entry. Once a rule detects a vulnerability at an
injection point (base request, location, parameter, value or name), the
remaining payloads of that point whose type the rule judges (``PAYLOAD_TYPES``
of ``fwa/oracle/<rule>.py``) are not sent.

Out-of-band interactions are polled only after the fuzzing, so an
``oast_interaction`` observation never stops an injection point.
"""
import json
from dataclasses import asdict, dataclass

from fwa import analyzer_manager as am
from fwa import oracle_manager as om
from fwa.utils import har, helper, payloads, webserver

REPORT_FILE = "early_stop.json"


class EarlyStopError(RuntimeError):
    """The online oracle cannot pair a fuzz request with its recorded entry."""


@dataclass(frozen=True)
class InjectionPoint:
    """Where a payload is injected: ``injected`` is "value" or "name" of the parameter."""

    request_index: int
    location: str
    parameter: str
    injected: str


@dataclass(frozen=True)
class Stop:
    """The payload whose observation made ``rule`` stop the injection point."""

    point: InjectionPoint
    rule: str
    payload: str
    payload_type: str


@dataclass(frozen=True)
class Skip:
    """A payload not sent because ``rule`` had already stopped the injection point."""

    point: InjectionPoint
    rule: str
    payload: str
    payload_type: str


@dataclass(frozen=True)
class Report:
    stops: list[Stop]
    skipped: list[Skip]

    def to_json(self):
        def flat(item):
            fields = asdict(item)
            return {**fields.pop("point"), **fields}
        return {"stops": [flat(s) for s in self.stops], "skipped": [flat(s) for s in self.skipped]}


def fuzz(fuzz_reqs, valid_entries, payload_rows, entries_file, send, progress) -> Report:
    """Send ``fuzz_reqs`` in order with ``send``, skipping the payloads of stopped injection points.

    Args:
        fuzz_reqs (list[Request]): fuzz requests with ``har_index``, ``fuzz_point`` and ``fuzz_payload``
        valid_entries (list[HarEntry]): the entries of the fuzzed session, by ``har_index``
        payload_rows (list[Payload]): the payload file rows
        entries_file (str): the entries file the recording proxy appends to
        send (callable): sends a request, returns its response or None (no response)
        progress (callable): called with the number of requests processed
    """
    # The XSS analyzer writes its files in ~/.fwa and opens the response from fwa's static web server.
    helper.fwa_init()
    analyzers = am.prepare(helper.fwa_default_analyzers_path())
    rules = om.get_rules(om.get_default_oracle_path())
    judged = {rule: om.payload_types(rule) for rule in rules}
    # For each stopped injection point, the rule that stopped each payload type.
    stopped: dict[InjectionPoint, dict[str, str]] = {}
    stops, skipped = [], []
    webserver.start_webserver()
    try:
        with open(entries_file, encoding="utf-8") as stream:
            for done, req in enumerate(fuzz_reqs, start=1):
                point = InjectionPoint(req.har_index, *req.fuzz_point)
                payload_type = payloads.type(payload_rows, req.fuzz_payload)
                rule = stopped.get(point, {}).get(payload_type)
                if rule is not None:
                    skipped.append(Skip(point, rule, req.fuzz_payload, payload_type))
                    progress(done)
                    continue
                response = send(req)
                entries = [json.loads(line) for line in stream.readlines()]
                if len(entries) != (0 if response is None else 1):
                    raise EarlyStopError("payload {!r} of {}: {} recorded entries for {} response".format(
                        req.fuzz_payload, point, len(entries), "no" if response is None else "one"))
                for entry in entries:
                    entry['payload'] = har.find_payload(entry, payload_rows)
                    # fwa analyze does not observe an entry without a known payload either.
                    if not entry['payload']:
                        continue
                    valid_entry = valid_entries[req.har_index]
                    obs = am.observe(analyzers, har.parse_url(valid_entry['request']['url']), valid_entry, entry)
                    for present in om.present_rules(obs, rules):
                        types = stopped.setdefault(point, {})
                        if present not in types.values():
                            stops.append(Stop(point, present, obs['payload'], obs['payload_type']))
                        for judged_type in judged[present]:
                            types.setdefault(judged_type, present)
                progress(done)
    finally:
        webserver.stop_webserver()
    return Report(stops, skipped)


def write_report(report: Report, path=REPORT_FILE):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_json(), f, ensure_ascii=False, indent=2)
    helper.info("Write {}".format(path))
