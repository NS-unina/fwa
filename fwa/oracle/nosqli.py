from fwa.analyzers.strings_in_response import NOSQL_ERRORS
from fwa.utils.observations import delayed, flag, new_keyword, server_error

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('NOSQL', 'NOSQL_TIME_BASED')


def oracle(obs):
    return obs['payload_type'] == 'NOSQL' and flag(obs, 'content_length') or \
           obs['payload_type'] == 'NOSQL' and server_error(obs) or \
           obs['payload_type'] == 'NOSQL' and any(new_keyword(obs, k) for k in NOSQL_ERRORS) or \
           obs['payload_type'] == 'NOSQL_TIME_BASED' and delayed(obs)
