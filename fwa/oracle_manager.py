import csv
import importlib
import os

from fwa.utils import helper

def get_observations(analyzer_file):
    ret = []
    with open(analyzer_file) as csv_file: 
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                line_count += 1 

            ret.append(row)

    return ret

def _get_rules(rules_path):
    rules = []
    for filename in os.listdir(rules_path):
        if filename.endswith(".py"):
            rules.append(filename)
    return rules

def _run_analyzer(filename, obs):
    module_name = filename.replace(".py", "")
    # print(module_name)
    module = importlib.import_module("fwa.oracle.{}".format(module_name))
    if hasattr(module, "oracle"):
        return {
            'vulnerability' : module_name, 
            'is_present'    : module.oracle(obs),
            'observations' : obs
        }
    else: 
        helper.warn("{} does not contain oracle function".format(module_name))
        return {
            'vulnerability' : module_name, 
            'is_present' : False,
            'observations':  obs
        }

def get_default_oracle_path():
    return os.path.join(helper.get_project_root(), 'oracle')

def get_rules(rules_path):
    """The names of the oracle rules of ``rules_path``."""
    return [r.replace(".py", "") for r in _get_rules(rules_path)]

def present_rules(obs, rules):
    """The rules (names) whose oracle detects a vulnerability in the observation ``obs``."""
    return [r for r in rules if _run_analyzer(r + ".py", obs)['is_present']]

def payload_types(rule):
    """The payload types the oracle rule ``rule`` judges (its ``PAYLOAD_TYPES``)."""
    module = importlib.import_module("fwa.oracle.{}".format(rule))
    if not hasattr(module, "PAYLOAD_TYPES"):
        raise AttributeError("oracle rule {} does not declare PAYLOAD_TYPES".format(rule))
    return module.PAYLOAD_TYPES

def write_results(output_file, results):
    with open(output_file, 'w') as f:
        fnames = results[0].keys()
        writer = csv.DictWriter(f, fieldnames=fnames)
        writer.writeheader()
        for c in results:
            writer.writerow(c)


def oracle(analyzer_file, rules_path, output_file, save_no_vulns):
    observations = get_observations(analyzer_file)
    rules = _get_rules(rules_path)
    ret = []
    for obs in observations:
        for r in rules: 
            results =  _run_analyzer(r, obs)
            # If save no vuln stores all 
            if save_no_vulns or (results and results['is_present']):
                ret.append(results)

    for r in ret:
        # adjust output
        observations = r['observations']
        del r['observations']
        r.update(observations)
        # with open(output_file, 'w') as f: 
    if len(ret) == 0:
        helper.warn("No vulnerability found, results file is not written")

    else:
        write_results(output_file, ret)
        helper.info("Write {}".format(output_file))


