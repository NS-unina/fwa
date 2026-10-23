from fwa.analyzers.strings_in_response import COMPUTED_MARKER
from fwa.utils.observations import delayed, flag, new_keyword

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('CMDI', 'CMDI_TIME_BASED', 'CMDI_OAST')


def oracle(obs):
    return obs['payload_type'] == 'CMDI' and flag(obs, 'a2cf52ff63502c5869b2813af3f455b6d0c00b0a_in_response') and not flag(obs, 'echo_in_response') or \
            obs['payload_type'] == 'CMDI' and flag(obs, 'root_in_response') and flag(obs, 'sbin_in_response') or \
            obs['payload_type'] == 'CMDI' and new_keyword(obs, COMPUTED_MARKER) or \
            obs['payload_type'] == 'CMDI_TIME_BASED' and delayed(obs) or \
            obs['payload_type'] == 'CMDI_OAST' and flag(obs, 'oast_interaction')
