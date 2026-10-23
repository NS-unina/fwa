"""Out-of-band interaction: an Interactsh payload domain of the fuzz request was contacted.

The interactions are the JSON lines written by interactsh-client (``-json -o``)
for the payloads of the fuzzed parameter; their path is ``FWA_OAST_INTERACTIONS``.
Without it no out-of-band channel is configured and no payload can have an
interaction; a configured path that does not exist is an error.
"""
import json
import os
import re

INTERACTIONS_ENV = "FWA_OAST_INTERACTIONS"
# An Interactsh payload host: <correlation id + nonce>.<server domain>.
PAYLOAD_LABEL = re.compile(r"([a-z0-9]{20,})\.", re.IGNORECASE)

_interacted = None


def _interacted_ids():
    global _interacted
    if _interacted is None:
        path = os.environ.get(INTERACTIONS_ENV)
        _interacted = set()
        if path:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        interaction = json.loads(line)
                        _interacted.add(interaction["full-id"].lower())
                        _interacted.add(interaction["unique-id"].lower())
    return _interacted


def analyze(valid_entry, fuzz_entry):
    payload = fuzz_entry.get('payload') or {}
    labels = {label.lower() for label in PAYLOAD_LABEL.findall(str(payload.get('value', '')))}
    return {'oast_interaction': bool(labels & _interacted_ids())}
