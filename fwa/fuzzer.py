from queue import Queue
import sys
from threading import Thread
from time import sleep
from copy import deepcopy
from datetime import datetime
from datetime import timezone
import json
import os
import tempfile
from urllib.parse import urlencode, urlparse, quote
from urllib.parse import parse_qs
from fwa import early_stop as es
from fwa.utils import bodies, har, helper, mitm
from fwa.utils.net import wait_for_port
import fwa.utils.payloads as p

import requests
# Disable warning ssl
import urllib3

from fwa.utils.helper import FWA_PREFIX, ProgressBar, fuzz_all, fwa_session, to_dict
urllib3.disable_warnings()


# Usually ping sleep payload are about 30 seconds
DEFAULT_TIMEOUT = 50
MITM_HOST = "127.0.0.1"
MITM_PORT = 8080
MITM_PROXY = "{}:{}".format(MITM_HOST, MITM_PORT)
MITM_STARTUP_TIMEOUT = 30
q = Queue()
# Global progress bar
pb = None
current_req = 0

def send_fuzz_requests():
    """ The following method runs the fuzz request by using threads
    """
    global q 
    global current_req 
    while True:
        fuzz_req = q.get()

        resp = send_request(fuzz_req, MITM_PROXY)
        current_req = current_req + 1
        pb.print(current_req)
        q.task_done()



methods = {
    "GET": requests.get,
    "POST": requests.post,
    "PUT": requests.put,
    "PATCH": requests.patch,
    "DELETE": requests.delete
}

# Attributes fuzzed by value only (no injection in the parameter names).
VALUE_ONLY_ATTRIBUTES = ("json_body", "xml_params", "path_params")

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
        # Non-form bodies and URL path segments: see fwa.utils.bodies
        self.json_body = None
        self.xml_body = None
        self.xml_params = {}
        self.path_params = bodies.path_params(self.url)
        # Position of the request in its HAR file, and of a fuzz request the
        # (attribute, parameter, "value" | "name") it injects and its payload.
        self.har_index = None
        self.fuzz_point = None
        self.fuzz_payload = None

    def set_json_body(self, text):
        self.json_body = json.loads(text)

    def set_xml_body(self, text):
        self.xml_body = text
        self.xml_params = bodies.xml_params(text)

    def xml_text(self):
        return bodies.xml_with_values(self.xml_body, self.xml_params)

    def base_url(self):
        """The URL without query string, with the current path segments."""
        parsed_url = urlparse(self.url)
        segments = parsed_url.path.split('/')
        for index, segment in self.path_params.items():
            segments[int(index)] = segment
        return "{}://{}{}".format(parsed_url.scheme, parsed_url.netloc, '/'.join(segments))

    def complete_url(self):
        # return self.url + "?" + urlencode(self.query_params)
        # To avoid invalid urlencode conditions
        return self.base_url() + "?" + helper.create_query_string(self.query_params)
    
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

    def get_fuzz_reqs(self, attribute, payloads, param=None):
        """Get the fuzz requests

        Args:
            attribute (str): The type of attribute
            payloads (list): The list of payloads
            param (str, optional): If set, fuzz only the value of this parameter (no name injection)
        """
        reqs = []
        obj_attr = getattr(self, attribute)
        if not isinstance(obj_attr, dict):
            # No JSON body, or a JSON body that is not an object: no parameters
            return reqs
       
        names = obj_attr.keys()
        if param is not None:
            names = [n for n in names if n == param]
        # For each payload take the n name of the parameter and set the payload as value
        for p in payloads:
            for n in names:
                r = deepcopy(self)
                getattr(r, attribute)[n] = self._fuzz_value(attribute, p)
                r.fuzz_point, r.fuzz_payload = (attribute, n, "value"), p
                reqs.append(r)

        if param is not None or attribute in VALUE_ONLY_ATTRIBUTES:
            return reqs

        # Add also parameters 
        for n in names:
            for p in payloads: 
                r = deepcopy(self)
                val = getattr(r, attribute)[n]
                del getattr(r, attribute)[n]
                getattr(r, attribute)[quote(p)] = val
                r.fuzz_point, r.fuzz_payload = (attribute, n, "name"), p
                # Remove previous attribute
                reqs.append(r)


        return reqs



    @staticmethod
    def _fuzz_value(attribute, payload):
        # Header values are sent as they are: no server URL-decodes them.
        if attribute == "headers":
            return payload
        if attribute == "json_body":
            return bodies.json_value(payload)
        # Escaped when the XML body is serialized.
        if attribute == "xml_params":
            return payload
        if attribute == "path_params":
            return bodies.path_segment(payload)
        return quote(payload)

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

class HarParser:
    def from_file(har_file):
        requests = []
        with open(har_file) as f:
            data = json.load(f)

        entries = data['log']['entries']
        for index, e in enumerate(entries):
            req = e['request']
            # print(req['url'], req['method'], req['cookies'], req['headers'])
            req_obj = Request(req['url'], req['method'], req['cookies'], req['headers'])
            req_obj.har_index = index
            requests.append(req_obj)
            if req['method'] == "POST":
                req_obj.body = to_dict(req['postData'].get('params', []))
            mime_type = req.get('postData', {}).get('mimeType', '')
            if 'json' in mime_type:
                req_obj.set_json_body(req['postData']['text'])
            elif 'xml' in mime_type:
                req_obj.set_xml_body(req['postData']['text'])

        return requests



json_obj = []


def send_request(req : Request, proxy = None):
    req_function = methods[req.method]
    the_url = urlparse(req.url).scheme
    try:
        if the_url != 'http' and the_url != 'https':
            print("[-] Invalid scheme protocol: {}".format(the_url))
        else:
            req.timestamp_start = helper.timestamp()
            if 'Cookie' in req.headers.keys():
                del req.headers['Cookie']

            if req.json_body is not None or req.xml_body is not None:
                if req.json_body is not None:
                    data, content_type = json.dumps(req.json_body), "application/json"
                else:
                    data, content_type = req.xml_text(), req.headers.get('Content-Type', "application/xml")
                req.headers['Content-Type'] = content_type
                url = req.complete_url() if req.query_params else req.base_url()
                resp = requests.request(req.method, url, cookies = req.cookies, proxies = {"http" : proxy, "https" : proxy}, verify = False, data = data.encode('utf-8'), headers = req.headers, allow_redirects=False, timeout=DEFAULT_TIMEOUT)
            elif req.method == "POST":
                # Fix header 
                req.headers['Content-Type'] = "application/x-www-form-urlencoded"
                resp = requests.post(req.base_url(), cookies = req.cookies, proxies = {"http" : proxy, "https" : proxy}, verify = False, data = helper.create_query_string(req.body), headers = req.headers, allow_redirects=False, timeout=DEFAULT_TIMEOUT)
                # json dumps to avoid encoding
            else:
                resp = req_function(req.complete_url(), cookies = req.cookies, proxies = {"http" : proxy, "https" : proxy}, verify = False, headers = req.headers, allow_redirects= False, timeout=DEFAULT_TIMEOUT)
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

def fuzz_from_har(session_name, payload_file, querystring, body, cookies, headers, threads, param=None,
                  json_body=False, xml_body=False, path_segments=False, early_stop=False,
                  simple_payloads_first=False):
    """Fuzz a session.

    With ``simple_payloads_first``, the payloads are sent in ``payloads.simple_first`` order;
    with ``early_stop``, each injection point stops as its oracle detects (fwa.early_stop).
    """
    global pb
    if early_stop and threads != 1:
        helper.err("--early-stop sends the payloads in order, one at a time: it needs --threads 1")
    har_file = fwa_session(session_name)
    requests = HarParser.from_file(har_file)
    fuzz_session_name = "{}{}".format(FWA_PREFIX, session_name)
    entries_file = ""
    if early_stop:
        handle, entries_file = tempfile.mkstemp(prefix="fwa-entries-", suffix=".jsonl")
        os.close(handle)
    # Quiet mode
    mitm.start_record("*", fuzz_session_name, True, True, entries_file)
    payload_rows = p.load(payload_file)
    if simple_payloads_first:
        payload_rows = p.simple_first(payload_rows)
    payloads = p.payloads(payload_rows)
    fuzz_reqs = []
    flows = []
    print(helper.get_project_root())
    print("Reqs no: {}".format(len(requests)))
    r : Request
    if fuzz_all([querystring, body, cookies, headers]):
            helper.info("Fuzz everything")
    helper.info("Num of threads: {}".format(threads))
    for r  in requests:
        ### FD
        # IF all set to false (default), fuzz everything
        # print(fuzz_all([querystring, body, cookies, headers]))
        # json_body, xml_body and path_segments are fuzzed only when requested
        if fuzz_all([querystring, body, cookies, headers]) and not (json_body or xml_body or path_segments):
            q_reqs = r.get_fuzz_reqs("query_params", payloads, param)
            c_reqs = r.get_fuzz_reqs("cookies", payloads, param)
            h_reqs = r.get_fuzz_reqs("headers", payloads, param)
            b_reqs = r.get_fuzz_reqs("body", payloads, param)
            fuzz_reqs.extend(q_reqs)
            fuzz_reqs.extend(c_reqs)
            fuzz_reqs.extend(h_reqs)
            fuzz_reqs.extend(b_reqs)

        # Conditional fuzzing
        else:
            if querystring: 
                helper.info("Fuzz querystring")
                q_reqs = r.get_fuzz_reqs("query_params", payloads, param)
                fuzz_reqs.extend(q_reqs)
            if body:
                helper.info("Fuzz body")
                b_reqs = r.get_fuzz_reqs("body", payloads, param)



                fuzz_reqs.extend(b_reqs)
            if cookies: 
                helper.info("Fuzz cookies")
                c_reqs = r.get_fuzz_reqs("cookies", payloads, param)
                fuzz_reqs.extend(c_reqs)
            if headers: 
                helper.info("Fuzz headers")
                h_reqs = r.get_fuzz_reqs("headers", payloads, param)
                fuzz_reqs.extend(h_reqs)
            if json_body:
                helper.info("Fuzz JSON body")
                fuzz_reqs.extend(r.get_fuzz_reqs("json_body", payloads, param))
            if xml_body:
                helper.info("Fuzz XML body")
                fuzz_reqs.extend(r.get_fuzz_reqs("xml_params", payloads, param))
            if path_segments:
                helper.info("Fuzz URL path segments")
                fuzz_reqs.extend(r.get_fuzz_reqs("path_params", payloads, param))

    print("Fuzz reqs {}".format(len(fuzz_reqs)))
    if param is not None and not fuzz_reqs:
        helper.err("Parameter \"{}\" not found in the selected locations of session \"{}\"".format(param, session_name))
    # Wait the start of the mitmproxy
    wait_for_port(MITM_HOST, MITM_PORT, MITM_STARTUP_TIMEOUT)
    if early_stop:
        pb = ProgressBar(len(fuzz_reqs))
        try:
            report = es.fuzz(fuzz_reqs, har.get_entries(har_file), payload_rows, entries_file,
                                    lambda req: send_request(req, MITM_PROXY), pb.print)
        finally:
            os.remove(entries_file)
        es.write_report(report)
        print("[+] Fuzz completed: {} payloads skipped".format(len(report.skipped)))
        mitm.stop_record()
        return
    for f in fuzz_reqs: 
        q.put(f)

    for t in range(threads):
        worker = Thread(target = send_fuzz_requests)
        worker.daemon = True 
        worker.start()
    

    pb = ProgressBar(len(fuzz_reqs))
    # for r  in fuzz_reqs:
    #     print("Req {} - ".format(i))
    #     resp = send_request(r, MITM_PROXY)
    #     i = i + 1
    #     pb.print(i)
    # All threads are completed 
    q.join()
    print("[+] Fuzz completed")
    mitm.stop_record()

    

def print_from_har(har_file, ):
    requests = HarParser.from_file(har_file)
    for r in requests:
        print(r.complete_url())

def urls_from_har(har_file):
    requests = HarParser.from_file(har_file)
    return [r.url for r in requests]
