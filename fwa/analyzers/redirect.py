from urllib.parse import urljoin, urlsplit

from fwa.analyzers.payload_reflection import payload_value


def _location(entry):
    for header in entry['response']['headers']:
        if header['name'].lower() == 'location':
            return header['value']
    return ''


def analyze(valid_entry, fuzz_entry):
    """The analyzer returns 1 if the fuzz response redirects (3xx + Location) to the host
    named by the payload, and that host is not the host of the request

    Args:
        valid_entry and fuzz_entry
    """
    request_url = fuzz_entry['request']['url']
    payload_host = urlsplit(payload_value(fuzz_entry)).hostname
    location = _location(fuzz_entry)
    redirected = 300 <= fuzz_entry['response']['status'] < 400 and location != ''
    location_host = urlsplit(urljoin(request_url, location)).hostname if redirected else None
    return {
        'redirect_to_payload_host': 1 if payload_host is not None and location_host == payload_host
                                         and payload_host != urlsplit(request_url).hostname else 0
    }
