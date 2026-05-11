import sys
import os
from har import *
import csv


SAFE_PAYLOADS = ['textvalue2', 'textvalue', '/wEPDwUENTM4MWRkhsjF 62gWnhYUcEyuRwTHxGDVzA=', '1234']

def get_findings_for_xss():
    ret = []
    har_entries : list[HarEntry] = get_entries(os.path.join('Findings', 'xss-findings.har'))
    for h in har_entries:
        req = h['request']
        query_string = req['queryString']
        for q in query_string:
            v = q['value']
            if v not in SAFE_PAYLOADS:
                ret.append({'url' : parse_url(req['url']), 'payload': v, 'vulnerability' : 'XSS'})
    return ret

    return ret
def get_findings_for_sqli():
    ret = []
    har_entries : list[HarEntry] = get_entries(os.path.join('Findings', 'sqli-findings.har'))
    for h in har_entries:
        req = h['request']
        query_string = req['queryString']
        for q in query_string:
            v = q['value']
            if v not in SAFE_PAYLOADS:
                ret.append({'url' : parse_url(req['url']), 'payload': v, 'vulnerability' : 'SQLI'})

    return ret


def get_findings_for_lfi():
    ret = []
    har_entries : list[HarEntry] = get_entries(os.path.join('Findings', 'lfi-findings.har'))
    for h in har_entries:
        req = h['request']
        query_string = req['queryString']
        ret.append({'url' : parse_url(req['url']), 'payload': query_string[0]['value'], 'vulnerability' : 'LFI'})

    return ret
    
    # with open()

lfi_attacks = get_findings_for_lfi()
sqli_attacks  = get_findings_for_sqli()
xss_attacks  = get_findings_for_xss()
findings = lfi_attacks + xss_attacks + sqli_attacks
csv_filename = 'zap_wavsep_findings.csv'

# Writing the list of dictionaries to the CSV file
with open(csv_filename, 'w', newline='') as csv_file:
    fieldnames = ['url', 'payload', 'vulnerability']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    
    # Write the header
    writer.writeheader()
    
    # Write the data
    for finding in findings:
        writer.writerow(finding)


