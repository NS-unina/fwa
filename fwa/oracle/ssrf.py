from fwa.analyzers.strings_in_response import PASSWD_MARKER
from fwa.utils.observations import flag, new_keyword

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('SSRF', 'SSRF_OAST')


def oracle(obs):
    """In-band SSRF: the response carries a local file (file://) or a much larger fetched page;
    out-of-band SSRF: the server contacted the payload's Interactsh domain."""
    return obs['payload_type'] == 'SSRF' and new_keyword(obs, PASSWD_MARKER) or \
           obs['payload_type'] == 'SSRF' and flag(obs, 'content_length') or \
           obs['payload_type'] == 'SSRF_OAST' and flag(obs, 'oast_interaction')
