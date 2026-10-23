#!/usr/bin/env python3
"""Run fwa for the records of an adapter manifest (``manifest-fwa.json``).

Each record is one catalog request with its targets (labelled parameters fwa
can fuzz) and the vulnerability classes of a strategy policy
(``adapters/scan_inputs.py``). For every record the driver runs fwa's own
pipeline through its CLI:

1. ``fwa record`` + ``fwa replay``: send the record's request through fwa's
   recording proxy, giving the valid (baseline) session with a real response;
2. for each target, ``fwa fuzz --param``: fuzz only that parameter at its
   location with the payloads of the record's classes (``classes.json``);
3. ``fwa analyze`` and ``fwa oracle``: observations and per-rule verdicts.

With ``--simple-payloads-first``, fwa sends the payloads in-band first, then
time-based, then out-of-band, by ``Level`` within each (``fwa.utils.payloads``).
With ``--early-stop``, ``fwa fuzz --early-stop`` analyzes each response at once
and stops fuzzing a target for a class once its rule detects it
(``early_stop.json``: the stops and the payloads not sent); every stop must be
a detection of the offline ``analyze`` + ``oracle`` too.

The detections of a target are the verdicts of the oracle rules of the record's
classes over the observations of that parameter. All fwa artifacts of a record
are kept in ``<output>/<stem>/``, those of its i-th target in
``<output>/<stem>/target-<i>/``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fwa.utils import har as fwa_har
from fwa.utils.helper import FWA_PREFIX, fwa_default_analyzers_path, fwa_session_path
from fwa.utils.net import wait_for_port

# fwa fuzz option selecting each catalog location.
LOCATION_OPTIONS = {"query": "--querystring", "post": "--body", "cookie": "--cookies", "header": "--headers",
                    "json": "--json", "xml": "--xml", "path": "--path"}
MITM_HOST, MITM_PORT = "127.0.0.1", 8080
PROXY_TIMEOUT_SECONDS = 60
STOP_TIMEOUT_SECONDS = 120
# Per-record cost counters summed in run.json.
COST_COUNTS = ("payloads_sent", "http_requests")
# Out-of-band payloads (payloads.csv types *_OAST) carry this placeholder; each is
# replaced by its own Interactsh payload domain before the target is fuzzed.
OAST_PLACEHOLDER = "{oast}"
# Read by fwa/analyzers/oast_interaction.py: the interactions of the target's payload domains.
INTERACTIONS_ENV = "FWA_OAST_INTERACTIONS"
OAST_START_TIMEOUT_SECONDS = 60
# interactsh-client's own default polling period.
INTERACTSH_CLIENT_POLL_SECONDS = 5


class FwaError(RuntimeError):
    """An fwa step failed or produced an unusable result."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_classes(path: Path) -> dict[str, dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["classes"]


def class_payloads(payload_file: Path, payload_types: list[str]) -> list[dict[str, str]]:
    """Rows of payloads.csv whose Type is one of ``payload_types``; every type must have rows."""
    with payload_file.open(newline="", encoding="utf-8") as handle:
        rows = [{key.strip(): value for key, value in row.items()} for row in csv.DictReader(handle)]
    selected = [row for row in rows if row["Type"] in payload_types]
    missing = sorted(set(payload_types) - {row["Type"] for row in selected})
    if missing:
        raise FwaError(f"{payload_file} has no payloads of type {missing}")
    return selected


def write_payloads(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["Payload", "Type", "Level"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run_fwa(arguments: list[str], cwd: Path, log: Path, env: dict[str, str] | None = None) -> None:
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"$ fwa {' '.join(arguments)}\n")
        handle.flush()
        completed = subprocess.run(["fwa", *arguments], cwd=cwd, stdout=handle, stderr=subprocess.STDOUT, env=env)
    if completed.returncode != 0:
        tail = "".join(log.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)[-30:])
        raise FwaError(f"fwa {arguments[0]} exited with {completed.returncode}; last lines of {log}:\n{tail}")


def wait_proxy_stopped() -> None:
    """fwa stops its recording proxy without waiting; the HAR is written when mitmdump exits."""
    deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
    while subprocess.run(["pgrep", "-f", "mitmdump"], stdout=subprocess.DEVNULL).returncode == 0:
        if time.monotonic() > deadline:
            raise FwaError(f"mitmdump still running {STOP_TIMEOUT_SECONDS}s after fwa stopped it")
        time.sleep(0.2)


@dataclass(frozen=True)
class OastSettings:
    """The Interactsh server the out-of-band payloads point to."""

    server: str
    token: str | None
    poll_seconds: int


class OastClient:
    """An interactsh-client run for one target: ``count`` payload domains and their interactions in ``work``.

    The client polls the server every ``poll_seconds``; ``finish`` waits two
    periods after the fuzzing, so an interaction made by the last request is
    polled, then stops the client.
    """

    def __init__(self, settings: OastSettings, count: int, work: Path, log: Path) -> None:
        self.settings = settings
        self.interactions = work / "oast-interactions.jsonl"
        payload_store = work / "oast-payloads.txt"
        self.interactions.touch()
        command = ["interactsh-client", "-s", settings.server, "-n", str(count), "-json", "-o", str(self.interactions),
                   "-ps", "-psf", str(payload_store), "-pi", str(settings.poll_seconds)]
        if settings.token:
            command += ["-t", settings.token]
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {' '.join(command)}\n")
            handle.flush()
            self.process = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + OAST_START_TIMEOUT_SECONDS
        while not (payload_store.is_file() and len(payload_store.read_text(encoding="utf-8").split()) >= count):
            if self.process.poll() is not None:
                raise FwaError(f"interactsh-client exited with {self.process.returncode} before registering; see {log}")
            if time.monotonic() > deadline:
                self.process.terminate()
                raise FwaError(f"interactsh-client did not register {count} payloads at {settings.server} "
                               f"within {OAST_START_TIMEOUT_SECONDS}s; see {log}")
            time.sleep(0.2)
        self.domains = payload_store.read_text(encoding="utf-8").split()[:count]

    def finish(self) -> dict[str, Any]:
        wait_seconds = 2 * self.settings.poll_seconds
        time.sleep(wait_seconds)
        self.process.terminate()
        self.process.wait(timeout=STOP_TIMEOUT_SECONDS)
        interactions = [line for line in self.interactions.read_text(encoding="utf-8").splitlines() if line.strip()]
        return {"payloads": len(self.domains), "interactions": len(interactions), "wait_seconds": wait_seconds}


@dataclass(frozen=True)
class FuzzOptions:
    """The ``fwa fuzz`` options that choose the order and the number of payloads sent."""

    early_stop: bool
    simple_payloads_first: bool

    def fwa_options(self) -> list[str]:
        return [*(["--early-stop"] if self.early_stop else []),
                *(["--simple-payloads-first"] if self.simple_payloads_first else [])]


def with_oast_domains(payloads: list[dict[str, str]], domains: list[str]) -> list[dict[str, str]]:
    """The payloads with each OAST placeholder replaced by its own domain, in order."""
    remaining = iter(domains)
    return [{**row, "Payload": row["Payload"].replace(OAST_PLACEHOLDER, next(remaining))}
            if OAST_PLACEHOLDER in row["Payload"] else row for row in payloads]


def har_entries(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FwaError(f"fwa did not write the session {path}")
    return json.loads(path.read_text(encoding="utf-8"))["log"]["entries"]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def sent_payloads(fuzz_har: Path, payloads: list[dict[str, str]], name: str, first_request_index: int,
                  record_started: float) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], int]:
    """Locate the requests of the payloads fuzzed into parameter ``name`` in ``fuzz_har``.

    fwa fuzz sends with one thread by default, so the HAR order is the send
    order. Returns, by payload value, its ``request_index`` in the record
    (``first_request_index`` for the first fuzz request) and the ``seconds``
    from the record's start to its response; the requests and response time of
    each payload type; and the number of requests whose payload fwa does not
    attribute to ``name``.
    """
    sent: dict[str, dict[str, Any]] = {}
    by_type: dict[str, dict[str, Any]] = {}
    entries = fwa_har.get_fuzz_entries(str(fuzz_har), payloads)
    for position, entry in enumerate(entries):
        used = entry["payload"]
        if not used or used["name"] != name:
            continue
        if used["value"] in sent:
            raise FwaError(f"{fuzz_har}: payload {used['value']!r} was sent more than once")
        responded = datetime.fromisoformat(entry["startedDateTime"]).timestamp() + entry["time"] / 1000
        sent[used["value"]] = {"request_index": first_request_index + position,
                               "seconds": round(responded - record_started, 3)}
        counts = by_type.setdefault(used["type"], {"requests": 0, "response_seconds": 0.0})
        counts["requests"] += 1
        counts["response_seconds"] += entry["time"] / 1000
    for counts in by_type.values():
        counts["response_seconds"] = round(counts["response_seconds"], 3)
    return sent, dict(sorted(by_type.items())), len(entries) - len(sent)


def read_early_stop(path: Path, name: str) -> dict[str, list[dict[str, Any]]]:
    """The stops and the skipped payloads of parameter ``name`` in fwa's ``early_stop.json``."""
    if not path.is_file():
        raise FwaError(f"fwa fuzz --early-stop did not write {path}")
    report = json.loads(path.read_text(encoding="utf-8"))
    def keep(item: dict[str, Any]) -> dict[str, Any]:
        return {key: item[key] for key in ("rule", "payload", "payload_type")}
    return {"stops": [keep(stop) for stop in report["stops"] if stop["parameter"] == name],
            "skipped_payloads": [keep(skip) for skip in report["skipped"] if skip["parameter"] == name]}


def fuzz_target(stem: str, target: dict[str, Any], payloads: list[dict[str, str]], payload_csv: Path,
                rule_classes: dict[str, str], work: Path, log: Path, first_request_index: int,
                record_started: float, oast: OastSettings | None, fuzz_options: FuzzOptions) -> dict[str, Any]:
    """Fuzz one target of the baseline session ``stem`` and read its oracle verdicts in ``work``.

    Out-of-band payloads get payload domains of their own (``OastClient``), so an
    interaction identifies the request that caused it.
    """
    sessions = Path(fwa_session_path())
    work.mkdir()
    # fwa's name of the parameter (a path segment is named by its index).
    name = target["fwa_parameter"]
    oast_count = sum(OAST_PLACEHOLDER in row["Payload"] for row in payloads)
    client = None
    if oast_count:
        if oast is None:
            raise FwaError(f"{stem}: {oast_count} out-of-band payloads need --interactsh-server")
        client = OastClient(oast, oast_count, work, log)
        payloads = with_oast_domains(payloads, client.domains)
        payload_csv = work / "payloads.csv"
        write_payloads(payload_csv, payloads)
    run_fwa(["fuzz", stem, "--payload-file", str(payload_csv), LOCATION_OPTIONS[target["location"]],
             "--param", name, *fuzz_options.fwa_options()], work, log)
    wait_proxy_stopped()
    fuzz_session = f"{FWA_PREFIX}{stem}"
    fuzz_entries = har_entries(sessions / f"{fuzz_session}.har")
    oast_report = client.finish() if client else None
    env = {**os.environ, INTERACTIONS_ENV: str(client.interactions)} if client else None

    # Observations and oracle verdicts (written in the working directory).
    run_fwa(["analyze", stem, fuzz_session, str(payload_csv)], work, log, env)
    run_fwa(["oracle", "observations.csv"], work, log)
    shutil.move(str(sessions / f"{fuzz_session}.har"), str(work / "fuzz.har"))
    sent, by_type, unattributed = sent_payloads(work / "fuzz.har", payloads, name, first_request_index, record_started)

    observations = [row for row in read_csv(work / "observations.csv") if row["fuzzed_param"] == name]
    observed = {row["payload"] for row in observations}
    stopping = read_early_stop(work / "early_stop.json", name) if fuzz_options.early_stop else None
    skipped = {skip["payload"] for skip in stopping["skipped_payloads"]} if stopping else set()
    # Cookie values are recorded URL-encoded, query and body values decoded.
    unobserved = [row["Payload"] for row in payloads if row["Payload"] not in observed
                  and quote(row["Payload"]) not in observed and row["Payload"] not in skipped]
    # The evidence of a detection is the request of its payload; fwa reports it
    # after the whole fuzzing, when analyze and oracle run (--early-stop: also online).
    detections = []
    for row in read_csv(work / "vulnerabilities.csv"):
        if row["vulnerability"] in rule_classes and row["fuzzed_param"] == name and row["is_present"] == "True":
            if row["payload"] not in sent:
                raise FwaError(f"{work}: detection payload {row['payload']!r} has no request in fuzz.har")
            detections.append({"vulnerability": rule_classes[row["vulnerability"]], "rule": row["vulnerability"],
                               "payload": row["payload"], "payload_type": row["payload_type"], **sent[row["payload"]]})
    # The online oracle analyzes the same recorded entries as the offline one.
    for stop in stopping["stops"] if stopping else []:
        if not any(d["rule"] == stop["rule"] and d["payload"] == stop["payload"] for d in detections):
            raise FwaError(f"{work}: fwa fuzz --early-stop stopped {name} for {stop['rule']} at payload "
                           f"{stop['payload']!r}, which fwa oracle does not detect")
    return {
        "parameter": target["parameter"],
        "location": target["location"],
        "fuzz_requests": len(fuzz_entries),
        "fuzz_by_payload_type": by_type,
        "unattributed_fuzz_requests": unattributed,
        "observations": len(observations),
        "unobserved_payloads": unobserved,
        # No observation of the parameter: the parameter was not tested.
        "status": "scanned" if observations else "not_attacked",
        "detections": detections,
        # Out-of-band payloads, interactions polled and the wait after the fuzzing.
        "oast": oast_report,
        # With --early-stop: the online detections that stopped a class, and the payloads not sent.
        "early_stop": stopping,
        "artifacts": f"{stem}/{work.name}",
    }


def scan_record(record: dict[str, Any], inputs_dir: Path, payload_file: Path, classes: dict[str, dict[str, Any]],
                output_dir: Path, oast: OastSettings | None, fuzz_options: FuzzOptions) -> dict[str, Any]:
    record_started = time.time()
    started = time.monotonic()
    stem = Path(record["input"]).stem
    work = output_dir / stem
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    log = work / "fwa.log"
    sessions = Path(fwa_session_path())
    sessions.mkdir(parents=True, exist_ok=True)

    configurations = {vulnerability: classes[vulnerability] for vulnerability in record["classes"]}
    payload_types = sorted({payload_type for configuration in configurations.values()
                            for payload_type in configuration["payload_types"]})
    payloads = class_payloads(payload_file, payload_types)
    write_payloads(work / "payloads.csv", payloads)
    request_session = f"{stem}-request"
    shutil.copyfile(inputs_dir / record["input"], sessions / f"{request_session}.har")

    # 1. Baseline: replay the request through the recording proxy.
    run_fwa(["record", "*", stem, "--quiet", "--background"], work, log)
    wait_for_port(MITM_HOST, MITM_PORT, PROXY_TIMEOUT_SECONDS)
    run_fwa(["replay", request_session, "--proxy", f"http://{MITM_HOST}:{MITM_PORT}"], work, log)
    run_fwa(["stop-record"], work, log)
    wait_proxy_stopped()
    baseline = har_entries(sessions / f"{stem}.har")
    if len(baseline) != 1:
        raise FwaError(f"{stem}: the baseline session has {len(baseline)} entries, expected 1")

    # 2-3. Fuzz each target alone, then analyze its observations.
    rule_classes = {configuration["rule"]: vulnerability for vulnerability, configuration in configurations.items()}
    # Request 1 is the baseline; the targets are fuzzed one after the other.
    targets = []
    for index, target in enumerate(record["targets"]):
        first_request_index = 1 + len(baseline) + sum(done["fuzz_requests"] for done in targets)
        targets.append(fuzz_target(stem, target, payloads, work / "payloads.csv", rule_classes, work / f"target-{index:02d}",
                                   log, first_request_index, record_started, oast, fuzz_options))
    for name, target in ((request_session, "request.har"), (stem, "baseline.har")):
        shutil.move(str(sessions / f"{name}.har"), str(work / target))

    response = baseline[0]["response"]
    fuzz_requests = sum(target["fuzz_requests"] for target in targets)
    type_classes = {payload_type: vulnerability for vulnerability, configuration in configurations.items()
                    for payload_type in configuration["payload_types"]}
    by_class: dict[str, dict[str, Any]] = {vulnerability: {"payloads_sent": 0, "seconds": 0.0, "skipped_payloads": 0}
                                           for vulnerability in sorted(configurations)}
    for target in targets:
        for payload_type, counts in target["fuzz_by_payload_type"].items():
            by_class[type_classes[payload_type]]["payloads_sent"] += counts["requests"]
            by_class[type_classes[payload_type]]["seconds"] += counts["response_seconds"]
        for skip in target["early_stop"]["skipped_payloads"] if target["early_stop"] else []:
            by_class[type_classes[skip["payload_type"]]]["skipped_payloads"] += 1
    for counts in by_class.values():
        counts["seconds"] = round(counts["seconds"], 3)
    return {
        "record": record,
        "classes": configurations,
        "payloads": len(payloads),
        "baseline_response": {"status": response["status"], "size": response["content"]["size"], "time_ms": baseline[0]["time"]},
        # A record with an untested target did not test all its parameters.
        "status": "scanned" if all(target["status"] == "scanned" for target in targets) else "not_attacked",
        # Requests recorded by fwa's proxy (those that got a response): payloads_sent
        # the fuzz requests, http_requests also the baseline; duration includes analyze and oracle.
        "cost": {"payloads_sent": fuzz_requests, "http_requests": len(baseline) + fuzz_requests,
                 "duration_seconds": round(time.monotonic() - started, 3),
                 # Fuzz requests, summed response times and early-stop skipped payloads of the types of each class.
                 "by_class": by_class},
        "targets": targets,
        "artifacts": stem,
    }


def run_metadata(payload_file: Path, classes: dict[str, dict[str, Any]], oast: OastSettings | None,
                 fuzz_options: FuzzOptions) -> dict[str, Any]:
    phantomjs = subprocess.run(["phantomjs", "--version"], capture_output=True, text=True, check=True).stdout.strip()
    return {
        "fwa_version": version("fwa"),
        "mitmproxy_version": version("mitmproxy"),
        "phantomjs_version": phantomjs,
        "interactsh_client_version": os.environ.get("INTERACTSH_CLIENT_VERSION"),
        "interactsh_server": oast.server if oast else None,
        "interactsh_poll_seconds": oast.poll_seconds if oast else None,
        "payloads": payload_file.name,
        "payloads_sha256": hashlib.sha256(payload_file.read_bytes()).hexdigest(),
        "early_stop": fuzz_options.early_stop,
        "simple_payloads_first": fuzz_options.simple_payloads_first,
        "analyzers": sorted(path.name for path in Path(fwa_default_analyzers_path()).glob("*.py")),
        "classes": classes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, required=True, help="manifest-fwa.json written by the adapter")
    parser.add_argument("--output", type=Path, required=True, help="directory for one JSON result per record and run.json")
    parser.add_argument("--payloads", type=Path, required=True, help="fwa payloads.csv")
    parser.add_argument("--classes", type=Path, required=True, help="classes.json")
    parser.add_argument("--interactsh-server", help="Interactsh server URL of the out-of-band payloads (e.g. http://oast.lab)")
    parser.add_argument("--interactsh-token", help="auth token of a protected Interactsh server")
    parser.add_argument("--upstream-proxy", help="HTTP proxy of the target traffic (e.g. the OYE engine)")
    parser.add_argument("--interactsh-poll-seconds", type=int, default=INTERACTSH_CLIENT_POLL_SECONDS,
                        help=f"interactsh-client polling period (its default {INTERACTSH_CLIENT_POLL_SECONDS})")
    parser.add_argument("--early-stop", action="store_true",
                        help="stop fuzzing a target for a class once fwa's online oracle detects it (fwa fuzz --early-stop)")
    parser.add_argument("--simple-payloads-first", action="store_true",
                        help="send in-band, then time-based, then out-of-band payloads, by Level (fwa fuzz --simple-payloads-first)")
    args = parser.parse_args(argv)
    if args.upstream_proxy:
        # fwa's recording mitmdump reads its options from ~/.mitmproxy/config.yaml (mitmproxy 9: mode is a list).
        mitmproxy_config = Path.home() / ".mitmproxy" / "config.yaml"
        mitmproxy_config.parent.mkdir(parents=True, exist_ok=True)
        mitmproxy_config.write_text(f"mode:\n  - upstream:{args.upstream_proxy}\n", encoding="utf-8")
    if args.interactsh_token and not args.interactsh_server:
        parser.error("--interactsh-token requires --interactsh-server")
    oast = (OastSettings(args.interactsh_server, args.interactsh_token, args.interactsh_poll_seconds)
            if args.interactsh_server else None)
    fuzz_options = FuzzOptions(args.early_stop, args.simple_payloads_first)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("tool") != "fwa":
        raise FwaError(f"{args.manifest} is a manifest for {manifest.get('tool')!r}, not fwa")
    records = [record for record in manifest["records"] if "input" in record]
    unsupported = [record for record in manifest["records"] if "input" not in record]
    classes = load_classes(args.classes)
    without_class = sorted({vulnerability for record in records for vulnerability in record["classes"]} - set(classes))
    if without_class:
        raise FwaError(f"no fwa class configuration for vulnerabilities {without_class} in {args.classes}")
    unknown_location = sorted({target["location"] for record in records for target in record["targets"]} - set(LOCATION_OPTIONS))
    if unknown_location:
        raise FwaError(f"fwa cannot fuzz locations {unknown_location}")
    out_of_band = sorted({vulnerability for record in records for vulnerability in record["classes"]
                          if any(OAST_PLACEHOLDER in row["Payload"]
                                 for row in class_payloads(args.payloads, classes[vulnerability]["payload_types"]))})
    if out_of_band and oast is None:
        parser.error(f"classes {out_of_band} have out-of-band payloads and need --interactsh-server")

    started = time.monotonic()
    run = {"started": _now(), "tool": "fwa", "manifest": str(args.manifest), "strategy": manifest.get("strategy"),
           "logged_in": manifest.get("logged_in", []),
           **run_metadata(args.payloads, classes, oast, fuzz_options)}
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for index, record in enumerate(records, start=1):
        result = scan_record(record, args.manifest.parent, args.payloads, classes, args.output, oast, fuzz_options)
        name = Path(record["input"]).stem + ".json"
        (args.output / name).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        targets = result["targets"]
        results.append({"result": name, "status": result["status"],
                        "detections": sum(len(target["detections"]) for target in targets),
                        "unobserved_payloads": sum(len(target["unobserved_payloads"]) for target in targets),
                        "skipped_payloads": sum(len(target["early_stop"]["skipped_payloads"]) for target in targets
                                                if target["early_stop"]),
                        "cost": result["cost"]})
        print(f"[{index}/{len(records)}] {result['status']} payloads={result['cost']['payloads_sent']} "
              f"requests={result['cost']['http_requests']} time={result['cost']['duration_seconds']:.1f}s "
              f"{record['policy']} {record['identifier'].split('|')[3]} "
              + " ".join(f"{target['parameter']}@{target['location']}:observations={target['observations']}/{result['payloads']}"
                         f",detected={sorted({d['vulnerability'] for d in target['detections']})}" for target in targets),
              flush=True)

    run.update({"finished": _now(), "duration_seconds": round(time.monotonic() - started, 3),
                "cost": {key: sum(result["cost"][key] for result in results) for key in COST_COUNTS},
                "results": results, "unsupported": unsupported})
    (args.output / "run.json").write_text(json.dumps(run, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    not_attacked = sum(result["status"] == "not_attacked" for result in results)
    incomplete = sum(result["unobserved_payloads"] > 0 for result in results)
    print(f"fwa: scanned={len(results) - not_attacked} not_attacked={not_attacked} "
          f"with_unobserved_payloads={incomplete} unsupported={len(unsupported)}")
    return 1 if not_attacked else 0


if __name__ == "__main__":
    sys.exit(main())
