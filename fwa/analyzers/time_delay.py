GREATER_THAN = 5

def analyze(valid_entry, fuzz_entry):
    """The analyzer returns True if the response time exceed a specific threshold

    Args:
        data (HarFuzzEntries): A HarFuzzEntries dictionary (validEntry, fuzzEntries)
    Returns:
        list: The list of delay for each fuzz request
    """
    time_valid = valid_entry['time'] + 0.001
    time_fuzz = fuzz_entry['time'] + 0.001

    return {
        'time_delay' : (time_fuzz / time_valid  > GREATER_THAN)
    }