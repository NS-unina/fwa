
import csv
from typing import TypedDict

class Payload(TypedDict):
    Payload :   str
    Type    :   str


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

def type(rows, payload):
    for r in rows:
        if r['Payload'] == payload:
            return r['Type']
    return None



