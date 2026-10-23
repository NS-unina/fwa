from fwa.utils.observations import flag

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('OPEN_REDIRECT',)


def oracle(obs):
    return obs['payload_type'] == 'OPEN_REDIRECT' and flag(obs, 'redirect_to_payload_host')
