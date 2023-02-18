import importlib
import os
from typing import TypedDict
from fwa.utils import har, helper
from fwa.utils.har import HarEntry, HarFuzzEntries, parse_url
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
import csv


from fwa.utils.payloads import Payload


class FuzzedPayload(TypedDict):
    name: str 
    value: str 
    type: str

# A single observation instance
class Observation(TypedDict): 
    url: str 
    fuzzed_param: str 
    payload: str 
    payload_type: str
    observations: list
    

def _get_analyzers(analyzers_path):
    analyzers = []
    for filename in os.listdir(analyzers_path):
        if filename.endswith(".py"):
            analyzers.append(filename)
    return analyzers


def _run_analyzer(filename, valid_entry, fuzz_entry):
    module_name = filename.replace(".py", "")
    # print(module_name)
    module = importlib.import_module("fwa.analyzers.{}".format(module_name))
    if hasattr(module, "analyze"):
        ret = module.analyze(valid_entry, fuzz_entry)
        return ret
    else: 
        helper.warn("{} does not contain analyze and header function".format(module_name))
        return {}

# def _get_header(filename):
#     module_name = filename.replace(".py", "")
#     module = importlib.import_module("fwa.analyzers.{}".format(module_name))
#     if hasattr(module, "analyze") and hasattr(module, 'header'):
#         ret = module.header()
#         return ret
#     else: 
#         helper.warn("{} does not contain analyze and header function".format(module_name))


def get_fuzz_entries(valid_entries, fuzz_entries) -> list[HarFuzzEntries]:
    """ For each valid entry return the list of relative fuzz entries.

    Args:
        valid_entries (list[HarEntry]): The list of valid har entries
        fuzz_entries (list[HarEntry]): The list of fuzzing har entries

    Returns:
        HarFuzzEntries: The list of har fuzz entries
    """
    ret = []
    for e in valid_entries:
        hfe : HarFuzzEntries = {}
        url = e['request']['url']
        url = parse_url(url)
        entries_by_url = har.get_entries_by_url(url, fuzz_entries)
        hfe['validEntry'] = e
        hfe['url'] = url
        hfe['fuzzEntries'] = entries_by_url
        ret.append(hfe)
    return ret


def write_analyzers(results_file, csv_entries):
    with open(results_file, 'w') as f:
        fnames = csv_entries[0].keys()
        writer = csv.DictWriter(f, fieldnames=fnames)
        writer.writeheader()
        for c in csv_entries:
            writer.writerow(c)

def run(session_name, fuzz_session_name, analyzers_path, payloads, results_file):
    """ Run all the analyzers, get results and write in the output file

    Args:
        analyzers_path (str): The path
    """
    analyzers = _get_analyzers(analyzers_path)
    # list<entry, <fuzz_strings_per_entry>
    fuzz_entries : list[HarFuzzEntries] = get_fuzz_entries(har.get_entries(helper.fwa_session(session_name)), har.get_fuzz_entries(helper.fwa_session(fuzz_session_name), payloads))
    csv_entries = []

    for fe in fuzz_entries: 
        valid_entry = fe['validEntry']
        all_fuzz_entries = fe['fuzzEntries']
        # Observations for a single url
        single_fuzz_observations = []
        for single_fuzz_entry in all_fuzz_entries:
            used_payload = single_fuzz_entry['payload']
            if used_payload:
                o = {}
                o['url'] = fe['url']
                o['fuzzed_param']  = used_payload['name']
                o['payload_type']  = used_payload['type']
                o['payload'] = used_payload['value']
                for a in analyzers: 
                    observations = _run_analyzer(a, valid_entry, single_fuzz_entry)
                    o.update(observations)
                csv_entries.append(o)
        


    write_analyzers(results_file, csv_entries)
                    # o[header] = observation
                # print(used_payload)
                # single_fuzz_observations.append(_run_analyzer(a, valid_entry, single_fuzz_entry)))
            
            # {'analyzer_name' : [ret]}
            # {'analyzer_name' : {'sub_name' : []}}
            # ['header' : [values]]
            # Returns: 
            # ret = ret + _run_analyzer(a, fe)
        

        # Completed the array, appaend all

        # If header is a string, 
        # print(ret)
        # if type(header) is str: 
        #     csv_entries[header] = ret
        # elif type(header) is list: 
        #     for i in range(0, len(header)):
        #         h = header[i]
        #         values = ret[i]
        #         # print(type(values))
        #         # print(h)


        # else: 
        #     print("Q")
        # csv_entries.append({header : ret})
        # print(csv_entries)
            
           # for v in ret:
            #     print(v)
            # print(ret)
