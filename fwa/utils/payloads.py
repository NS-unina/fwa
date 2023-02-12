
import csv

def load(csv_file):
    rows = []
    i = 0
    with open(csv_file) as f: 
        csv_reader = csv.DictReader(f)
        for r in csv_reader: 
            if i == 0:
                pass
            i = i +1
            rows.append(r)
    return rows

def payloads(rows):
    return [f['Payload'] for f in rows]

def type(rows, payload):
    for r in rows:
        if r['Payload'] == payload:
            return r['Type']
    return None



