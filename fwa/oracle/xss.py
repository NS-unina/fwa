from fwa.utils.observations import flag

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('XSS',)


def oracle(xss_obs):
    return xss_obs['payload_type'] == 'XSS' and flag(xss_obs, 'alert_executed')
