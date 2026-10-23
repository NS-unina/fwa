
import csv
from typing import TypedDict

class Payload(TypedDict):
    Payload :   str
    Type    :   str
    # Optional, needed by simple_first: 1 the payload alone (no context to break out of),
    # 2 it closes its injection context first, 3 it evades a filter or uses an
    # alternative representation.
    Level   :   str


def trim_dict_keys(d: dict):
    """Returns a new dictionary with trimmed keys
    Args:
        d (dict): The dictionary to modify
    """
    return {key.strip(): value for key, value in d.items()}

def load(csv_file) -> list[Payload]:
    rows = []
    i = 0
    with open(csv_file) as f: 
        csv_reader = csv.DictReader(f)
        for r in csv_reader: 
            if i == 0:
                pass
            i = i +1

            rows.append(trim_dict_keys(r))
    return rows

def payloads(rows):
    return [f['Payload'] for f in rows]

# Payload types whose evidence is not in the response: a time-based payload
# waits for a delay, an out-of-band one for an interaction (tiers 1 and 2).
BLIND_TYPE_SUFFIXES = ("_TIME_BASED", "_OAST")

def tier(payload_type):
    """0 for a payload with evidence in the response, 1 for a time-based one, 2 for an out-of-band one."""
    for index, suffix in enumerate(BLIND_TYPE_SUFFIXES, start=1):
        if payload_type.endswith(suffix):
            return index
    return 0

LEVELS = ("1", "2", "3")

def level(row):
    if row.get('Level') not in LEVELS:
        raise ValueError("payload {!r} has Level {!r}, expected one of {}".format(row['Payload'], row.get('Level'), LEVELS))
    return int(row['Level'])

def simple_first(rows):
    """The rows ordered by tier, then by Level, then by file order."""
    return sorted(rows, key=lambda r: (tier(r['Type']), level(r)))

def type(rows, payload):
    for r in rows:
        if r['Payload'] == payload:
            return r['Type']
    return None



