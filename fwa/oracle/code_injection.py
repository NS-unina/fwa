from fwa.analyzers.strings_in_response import COMPUTED_MARKER
from fwa.utils.observations import new_keyword

# The payload types this rule judges: once it detects a vulnerability at an injection
# point, fwa fuzz --early-stop does not send the remaining payloads of these types there.
PAYLOAD_TYPES = ('CODE_INJECTION',)


def oracle(obs):
    """The payload's expression was evaluated: its result, absent from the payload, is in the response."""
    return obs['payload_type'] == 'CODE_INJECTION' and new_keyword(obs, COMPUTED_MARKER)
