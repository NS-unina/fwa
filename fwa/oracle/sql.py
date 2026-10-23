from fwa.analyzers.strings_in_response import SQL_ERRORS
from fwa.utils.observations import delayed, flag, new_keyword, server_error

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('SQL', 'SQL_TIME_BASED')


def content_based(obs): 
    return 'content_length' in obs.keys() and flag(obs, 'content_length')
def time_based(obs):
    return 'time_delay' in obs.keys() and delayed(obs)
def error_based(obs):
    return flag(obs, 'SQL_in_response') and flag(obs, 'error_in_response') and not flag(obs, 'SQL_in_valid_response') or \
           any(new_keyword(obs, k) for k in SQL_ERRORS)

def oracle(obs):
    return obs['payload_type'] == 'SQL_TIME_BASED' and time_based(obs) or \
           obs['payload_type'] == 'SQL' and content_based(obs) or \
           obs['payload_type'] == 'SQL' and server_error(obs) or \
           obs['payload_type'] == 'SQL' and error_based(obs)
