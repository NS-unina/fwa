import json
from typing import TypedDict
from urllib.parse import quote, urlparse

from fwa.utils.payloads import Payload
# https://w3c.github.io/web-performance/specs/HAR/Overview.html#sec-object-types-entries

def parse_url(url):
    parsed_url = urlparse(url)
    # https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242
    return "{}://{}{}".format(parsed_url.scheme, parsed_url.netloc, parsed_url.path)

class HarParam(TypedDict):
    name: str 
    value: str

class HarContent(TypedDict):
    size: int 
    compression: int 
    mimeType: str 
    text: str 


class HarPostData(TypedDict):
    mimeType: str
    text: str
    params: list[HarParam]

class HarRequest(TypedDict):
    method: str
    url: str 
    httpVersion: str 
    cookies: list[HarParam]
    headers: list[HarParam]
    queryString: list[HarParam]
    headersSize : int 
    bodySize : int
    postData: HarPostData 


class HarResponse(TypedDict):
    status: int
    statusText : str
    httpVersion: str 
    cookies: list[HarParam]
    headers: list[HarParam]
    content: HarContent
    redirectURL: str 
    headersSize: int 
    bodySize: int 

class HarTimings(TypedDict):
    send:       int
    receive:    int 
    wait:       int 
    connect:    int 
    ssl:        int 

class HarEntry(TypedDict): 
    startedDateTime: str 
    time: int 
    request:    HarRequest 
    response:   HarResponse
    cache: dict 
    timings: dict 
    serverIPAddress: str

class HarFuzzEntries(TypedDict):
    validEntry: HarEntry 
    url: str
    fuzzEntries : list[HarEntry]


def get_entries(har_file) -> list[HarEntry]:
    har_entries = []
    with open(har_file) as f:
        data = json.load(f)

        entries = data['log']['entries']
        for e in entries: 
            he : HarEntry = e
            har_entries.append(he)
        return har_entries
            # req_obj = Request(req['url'], req['method'], req['cookies'], req['headers'])
        # if req['method'] == "POST"
        #     req_obj.body = to_dict(req['postData']['params'])

def get_fuzz_entries(har_file, payloads) ->list:
    """ Returns a list of HAR entry by adding some attributes (used payload)
    """
    har_entries = get_entries(har_file)
    for he in har_entries: 
        he['payload'] = find_payload(he, payloads)
    return har_entries


def get_entries_by_url(url: str, entries: list[HarEntry]):
    return [e for e in entries if parse_url(e['request']['url']) == url]

def _find_payload(params, payload: Payload):
    # Check also for url-encoded values in payload list
    for p in params: 
        if p['value'] == payload['Payload'] or p['value'] == quote(payload['Payload']):
            p['type'] = payload['Type']
            return p
    return None

def _find_from_payloads(params, payloads):
    for p in payloads: 
        found = _find_payload(params, p)
        if found: 
            return found
    return None

def find_payload(entry: HarEntry, payloads: list[Payload]): 
    """ Looks the presence of a payload in the entry

    Args:
        entry (HarEntry): _description_
        payloads (str): _description_

    Returns:
        _type_: _description_
    """
    found = None
    req = entry['request']

    if 'postData' in req.keys():
        params =req['postData']['params']
        found = _find_from_payloads(params, payloads)
        if found: 
            return found
    queryString = req['queryString']
    found = _find_from_payloads(queryString, payloads)
    if found: 
        return found


    headers = req['headers']
    found = _find_from_payloads(headers, payloads)
    if found: 
        return found

    cookies = req['cookies']
    found = _find_from_payloads(cookies, payloads)
    if found: 
        return found
    # NONE?
    return found

    

    # for k, v in req['cookies'].items():
    #     print(v)
    # for k, v in req['queryString'].items():
    #     print(v)