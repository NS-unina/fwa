
def analyze(valid_entry, fuzz_entry):
    """The analyzer returns the status code 

    Args:
        valid_entry and fuzz_entry
    Returns:
        1 if the date
    """
    # If the status code is the same we can put to TRUE
    original_status_code = valid_entry['response']['status']
    fuzz_resp = fuzz_entry['response']
    return {
        'status_code': fuzz_resp['status'],
        'status_code_is_different' : original_status_code != fuzz_resp['status']
    }
