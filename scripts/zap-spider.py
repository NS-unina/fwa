import time
from pprint import pprint
from zapv2 import ZAPv2

apikey = 'secsi' 
# mitmAddress = '127.0.0.1'
# mitmPort = 8080

# helper.log("Add mitm proxy")
# core.set_option_use_proxy_chain(boolean=True)
# core.set_option_proxy_chain_name(string=mitmAddress)
# core.set_option_proxy_chain_port(integer=mitmPort)

def zap_api():
    return helper.get_env('ZAP_API')
def zap_key():
    return helper.get_env('ZAP_API_KEY')


def open(target):
    return ZAPv2(apikey=zap_key(), proxies={'http':zap_api(), 'https': zap_api()})

# zap = ZAPv2(apikey=apikey)
# Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
def spider(target):
    """Run spider against a target

    Args:
        target (String): A full url

    Returns:
        list: A list containing urls found urls
    """
    zap = open(target)
    core = zap.core
    # Proxy a request to the target so that ZAP has something to deal with
    helper.log('Accessing target {}'.format(target))
    zap.urlopen(target)
    # Give the sites tree a chance to get updated
    time.sleep(2)

    # helper.log('Remove previous scans')
    # ret = zap.spider.remove_all_scans()
    helper.log('Spidering target {}'.format(target))
    scanid = zap.spider.scan(target)
    # Give the Spider a chance to start
    time.sleep(2)
    while (int(zap.spider.status(scanid)) < 100):
        # Loop until the spider has finished
        helper.log('Spider progress %: {}'.format(zap.spider.status(scanid)))
        time.sleep(2)

    helper.log('Spider completed')

    while (int(zap.pscan.records_to_scan) > 0):
        helper.log('Records to passive scan : {}'.format(zap.pscan.records_to_scan))
        time.sleep(2)

    helper.log('Passive Scan completed')

    # print ('Active Scanning target {}'.format(target))
    # scanid = zap.ascan.scan(target)
    # while (int(zap.ascan.status(scanid)) < 100):
    #     # Loop until the scanner has finished
    #     print ('Scan progress %: {}'.format(zap.ascan.status(scanid)))
    #     time.sleep(5)

    # print ('Active Scan completed')

    # Report the results
    return zap.spider.full_results(scanid)[0]['urlsInScope']
# print ('Alerts: ')
# pprint (zap.core.alerts())

def get_messages(target, messages):
    zap = open(target)
    core = zap.core
    ret = []
    helper.log('Accessing target {}'.format(target))
    for m in messages:
        ret.append(core.messages_by_id(m)[0])
    return ret