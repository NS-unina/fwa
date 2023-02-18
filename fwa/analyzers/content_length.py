PERCENTAGE_LENGTH = 500




def analyze(valid_entry, fuzz_entry):
    """The analyzer returns True if the content length exceed a percentage 

    Args:
        valid_entry and fuzz_entry
    Returns:
        1 if the date
    """
    valid_response = valid_entry['response']
    valid_size = valid_response['content']['size']
    fuzz_resp = fuzz_entry['response']
    fuzz_size = fuzz_resp['content']['size']
    if fuzz_size > valid_size + ((valid_size * PERCENTAGE_LENGTH) / 100):
        return {
            'content_length' : 1
        }
    else:
        return {
            'content_length': 0
        }
