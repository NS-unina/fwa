
def content_based(obs): 
    return 'content_length' in obs.keys() and obs['content_length'] == 1
def time_based(obs):
    return 'time_delay' in obs.keys() and obs['time_delay']  == 1

def oracle(obs):
    return obs['payload_type'] == 'SQL' and time_based(obs) or \
           obs['payload_type'] == 'SQL' and content_based(obs) or \
           obs['payload_type'] == 'SQL' and obs['status_code'] == 500 