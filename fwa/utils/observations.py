"""Typed reads of observation values for the oracle rules.

The oracle reads observations back from observations.csv, so every value is a
string ("1", "0", "True", "False", "500"); a rule called in memory gets the
ints and bools returned by the analyzers. These helpers accept both forms and
fail on anything else instead of relying on string truthiness ("0" is truthy).
"""

# Time-based payloads sleep 5 seconds; a fuzz response must be at least this
# much slower than the valid one, on top of the analyzer's ratio test.
MIN_DELAY_MS = 4000


def flag(obs, key):
    value = obs[key]
    if isinstance(value, bool):
        return value
    text = str(value).strip()
    if text in ("1", "True"):
        return True
    if text in ("0", "False"):
        return False
    raise ValueError("observation {!r} is not a 0/1 flag: {!r}".format(key, value))


def number(obs, key):
    return float(obs[key])


def new_keyword(obs, keyword):
    """The keyword is in the fuzz response and was not in the valid response."""
    return flag(obs, "{}_in_response".format(keyword)) and not flag(obs, "{}_in_valid_response".format(keyword))


def delayed(obs):
    """The time_delay analyzer fired and the delay is at least MIN_DELAY_MS."""
    return flag(obs, "time_delay") and number(obs, "time_delay_ms") >= MIN_DELAY_MS


def server_error(obs):
    """The fuzz request got a 500 while the valid request did not."""
    return int(obs["status_code"]) == 500 and flag(obs, "status_code_is_different")
