from time import sleep
from copy import deepcopy
from datetime import datetime
from datetime import timezone
import json
from urllib.parse import urlencode, urlparse, quote
from urllib.parse import parse_qs
from fwa.utils import helper, mitm
import fwa.utils.payloads as p

import requests
# Disable warning ssl
import urllib3

from fwa.utils.helper import ProgressBar, fwa_session, to_dict
urllib3.disable_warnings()

DEFAULT_TIMEOUT = 2
MITM_PROXY = "127.0.0.1:8080"

methods = {
    "GET": requests.get,
    "POST": requests.post,
    "PUT": requests.put,
    "DELETE": requests.delete
}

def default_headers():
    return {"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"}


class Request: 
    def __init__(self, url, method, cookies, headers, body = {}):
        self.url = self.parse_url(url)
        self.method = method 
        self.query_params = {k: v[0] for k, v in self.query_url(url).items()}
        # Think to avoid it for performance issue
        self.list_cookies = cookies
        self.list_headers = headers
        self.cookies = to_dict(cookies)
        self.headers = to_dict(headers)
        self.body = body

    def complete_url(self):
        return self.url + "?" + urlencode(self.query_params)
    
    def parse_url(self, url):
        parsed_url = urlparse(url)
        # https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242
        return "{}://{}{}".format(parsed_url.scheme, parsed_url.netloc, parsed_url.path)
        
    def query_url(self, url):
        parsed_url = urlparse(url)
        return parse_qs(parsed_url.query)

    def set(self, attribute, name, val):
        """Set a single attribute

        Args:
            attribute (str): Can be "cookies, headers or body
            name (str): The name of the internal param
            val (str): The value to set
        """
        getattr(self, attribute)[name] = val

    def get_fuzz_reqs(self, attribute, payloads):
        """Get the fuzz requests

        Args:
            attribute (str): The type of attribute
            payloads (list): The list of payloads
        """
        reqs = []
        obj_attr = getattr(self, attribute)
       
        names = obj_attr.keys()
        # For each payload take the n name of the parameter and set the payload as value
        for p in payloads:
            for n in names:
                r = deepcopy(self)
                getattr(r, attribute)[n] = quote(p)
                reqs.append(r)

        return reqs



    def header_names(self):
        return list(self.headers.keys())

    def body_names(self):
        return list(self.body.keys())

    def url_names(self): 
        """Returns the list of params

        Returns:
            list: The list of params
        """
        query = self.query_url()
        return list(query.keys())

# class HarEntry:

    


class HarParser:
    def from_file(har_file):
        requests = []
        with open(har_file) as f:
            data = json.load(f)

        entries = data['log']['entries']
        for e in entries: 
            req = e['request']
            # print(req['url'], req['method'], req['cookies'], req['headers'])
            req_obj = Request(req['url'], req['method'], req['cookies'], req['headers'])
            requests.append(req_obj)
            if req['method'] == "POST":
                req_obj.body = to_dict(req['postData']['params'])

        return requests



json_obj = []


def send_request(req, proxy = None):
    req_function = methods[req.method]
    the_url = urlparse(req.url).scheme
    try:
        if the_url != 'http' and the_url != 'https':
            print("[-] Invalid scheme protocol: {}".format(the_url))
        else:
            req.timestamp_start = helper.timestamp()

            if req.method == "POST":
                resp = requests.post(req.complete_url() , proxies = {"http" : proxy, "https" : proxy}, verify = False, data = req.body, headers = req.headers, allow_redirects=False, timeout=DEFAULT_TIMEOUT)
            else:
                resp = req_function(req.complete_url(), proxies = {"http" : proxy, "https" : proxy}, verify = False, headers = req.headers, allow_redirects= False, timeout=DEFAULT_TIMEOUT)
            req.timestamp_end = helper.timestamp()
            return resp
    except requests.exceptions.ReadTimeout:
        print(req.url)
        print("[-] Req exception timeout")


def send_from_har(session_name : str, proxy):
    har_file = fwa_session(session_name)
    requests = HarParser.from_file(har_file)
    for r in requests:
        # print("Send {}".format(r.url))
        send_request(r, proxy)

def fuzz_from_har(session_name, payload_file):
    har_file = fwa_session(session_name)
    requests = HarParser.from_file(har_file)
    fuzz_session_name = "fwa-{}".format(session_name)
    mitm.start_record(fuzz_session_name, False, True)
    payloads = p.payloads(p.load(payload_file))
    fuzz_reqs = []
    flows = []
    print("Reqs no: {}".format(len(requests)))
    for r in requests:
        q_reqs = r.get_fuzz_reqs("query_params", payloads)
        ### FD
        # c_reqs = r.get_fuzz_reqs("cookies", payloads)
        h_reqs = r.get_fuzz_reqs("headers", payloads)
        # b_reqs = r.get_fuzz_reqs("body", payloads)
        # fuzz_reqs.extend(q_reqs)
        # fuzz_reqs.extend(c_reqs)
        fuzz_reqs.extend(h_reqs)
        # fuzz_reqs.extend(b_reqs)
    print("Fuzz reqs {}".format(len(fuzz_reqs)))
    i = 0
    # Wait the start of the mitmproxy
    sleep(1)
    pb = ProgressBar(len(fuzz_reqs))
    for r in fuzz_reqs:
        print("Req {} - ".format(i))
        resp = send_request(r, MITM_PROXY)
        i = i + 1
        pb.print(i)
    
    mitm.stop_record()

    

def print_from_har(har_file, proxy):
    requests = HarParser.from_file(har_file)
    for r in requests:
        print(r.complete_url())

def urls_from_har(har_file):
    requests = HarParser.from_file(har_file)
    return [r.url for r in requests]
