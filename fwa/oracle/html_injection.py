from fwa.utils.observations import flag

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('HTMLI',)


def oracle(obs):
    """The HTML markup of the payload is in the response unencoded."""
    return obs['payload_type'] == 'HTMLI' and flag(obs, 'payload_reflected')
