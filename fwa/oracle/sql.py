
from fwa.utils.helper import pretty_print_json


def content_based(obs): 
    return 'content_length' in obs.keys() and obs['content_length'] == 1
def time_based(obs):
    return 'time_delay' in obs.keys() and obs['time_delay']  == 1

def oracle(obs):
    return obs['payload_type'] == 'SQL_TIME_BASED' and time_based(obs) or \
           obs['payload_type'] == 'SQL' and content_based(obs) or \
           obs['payload_type'] == 'SQL' and int(obs['status_code']) == 500  and obs['status_code_is_different'] or \
           obs['payload_type'] == 'SQL' and obs['SQL_in_response'] and obs['error_in_response'] and not obs['SQL_in_valid_response']