
def analyze(valid_entry, fuzz_entry):
    """The analyzer returns the status code 

    Args:
        valid_entry and fuzz_entry
    Returns:
        1 if the date
    """
    fuzz_resp = fuzz_entry['response']
    return {
        'status_code': fuzz_resp['status']
    }
