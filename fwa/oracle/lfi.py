

def oracle(obs):
    return obs['payload_type'] == 'LFI' and obs['root_in_response'] and obs['sbin_in_response']