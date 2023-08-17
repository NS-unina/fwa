

def oracle(xss_obs):
    return xss_obs['payload_type'] == 'XSS' and int(xss_obs['alert_executed']) == 1
