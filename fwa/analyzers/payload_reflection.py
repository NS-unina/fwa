from urllib.parse import unquote


def payload_value(fuzz_entry):
    """The injected payload as the application received it.

    Query and body values are recorded decoded; cookie values are recorded as
    sent (URL-encoded by the fuzzer); header values are sent as they are.
    """
    return unquote(fuzz_entry['payload']['value'])


def analyze(valid_entry, fuzz_entry):
    """The analyzer returns 1 if the payload is in the fuzz response verbatim (unencoded)
    and was not already in the valid response

    Args:
        valid_entry and fuzz_entry
    """
    payload = payload_value(fuzz_entry)
    html = fuzz_entry['response']['content'].get('text', '')
    valid_html = valid_entry['response']['content'].get('text', '')
    return {
        'payload_reflected': 1 if payload in html and payload not in valid_html else 0
    }
