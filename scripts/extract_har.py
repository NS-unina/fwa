

# name: extract_har.py
# The following script extracts a list of requests on the basis of an har file
#
#
import json
import sys
from typing import TypedDict
from urllib.parse import quote, urlparse

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



def get_entries_by_url(url: str, entries: list[HarEntry]):
    return [e for e in entries if parse_url(e['request']['url']) == url]

def get_entries_by_content(content: str, entries: list[HarEntry]):
    return [e for e in entries if content in parse_url(e['request']['url'])]


def change_entries(har_file, new_entries, output_file="output.har"):
    data = {}
    with open(har_file, 'r') as f:
        data = json.load(f)
        data['log']['entries'] = new_entries
    with open(output_file, 'w') as nf:
        json.dump(data, nf, ensure_ascii = False, indent=4)


def read_list():
    with open('list.txt') as f: 
        data = f.readlines()
    return [d.replace("\n", "") for d in data]

def e():
    sys.exit(-1)
if __name__ == '__main__' :
    har_file = "owasp-sqli.har"
    har_entries : list[HarEntry]= get_entries(har_file) 

    list_new : list[HarEntry] = []
    for l in read_list():
        uh = get_entries_by_content(l, har_entries)
        if len(uh) > 0:
            list_new = list_new + uh
    change_entries(har_file, list_new)

