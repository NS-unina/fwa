from fwa.utils.observations import flag

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('LFI',)


def oracle(obs):
    return obs['payload_type'] == 'LFI' and flag(obs, 'root_in_response') and flag(obs, 'sbin_in_response')
