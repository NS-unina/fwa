import json
from typing import TypedDict

class HarParam(TypedDict):
    name: str 
    value: str

class HarContent(TypedDict):
    size: int 
    compression: int 
    mimeType: str 
    text: str 
    redirectURL: str 
    headersSize: int 
    bodySize: int 
    cache: dict 
    timings: dict 
    serverIPAddress: str


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

class HarEntry(TypedDict): 
    startedDateTime: str 
    time: int 
    request:    HarRequest 
    response:   HarResponse


def get_har_entries(har_file) -> list[HarEntry]:
    har_entries = []
    with open(har_file) as f:
        data = json.load(f)

        entries = data['log']['entries']
        for e in entries: 
            he : HarEntry = e
            har_entries.append(he)
        return har_entries
            # req_obj = Request(req['url'], req['method'], req['cookies'], req['headers'])
        # if req['method'] == "POST":
        #     req_obj.body = to_dict(req['postData']['params'])