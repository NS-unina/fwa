

def oracle(obs):
    return obs['payload_type'] == 'CMDI' and int(obs['a2cf52ff63502c5869b2813af3f455b6d0c00b0a_in_response']) and not int(obs['echo_in_response']) or \
            obs['payload_type'] == 'CMDI' and int(obs['root_in_response']) and int(obs['sbin_in_response'])