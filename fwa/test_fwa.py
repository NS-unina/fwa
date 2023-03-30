import os
from fwa import fuzzer
from fwa.fuzzer import Request
from fwa.utils import har
from fwa.utils import helper
from fwa.utils.helper import fuzz_all

def req():
    url = "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&b=bb" 
    method = "POST" 
    cookies = [] 
    headers = [{'name': 'User-Agent', 'value': 'Apache-HttpClient/5.1.3 (Java/17.0.5)'}, {'name': 'Accept-Encoding', 'value': 'gzip, deflate, br'}, {'name': 'Accept', 'value': '*/*'}, {'name': 'Connection', 'value': 'keep-alive'}, {'name': 'Content-Type', 'value': 'application/x-www-form-urlencoded'}, {'name': 'Content-Length', 'value': '25'}, {'name': 'Host', 'value': 'localhost:8443'}]
    r = Request(url, method, cookies, headers)
    return r


def test_create_qs():
    r = {'a' : 'argsa' , 'b': 'argsb'}
    assert helper.create_query_string(r) == "a=argsa&b=argsb"
def test_parse_qs():
    # assert r.url_names() == ["a", "b"]
    r = req()
    assert r.header_names() == ["User-Agent", "Accept-Encoding", "Accept", "Connection", "Content-Type", "Content-Length", "Host"]

def test_set():
    r = req()
    r.set("headers", "User-Agent", "testing")
    assert r.headers["User-Agent"] == "testing"

def test_req():
    url = "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&b=bb" 
    r = req()
    assert r.query_params == {"a" : "aa", "b" : "bb"}
    assert r.url == "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242"
    assert r.complete_url() ==  url


def test_fuzz_req():
    r = req()
    payloads = ["xss", "sql", "cmdi"]
    urls = [
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=xss&b=bb",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&b=xss",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=sql&b=bb",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&b=sql",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=cmdi&b=bb",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&b=cmdi",
        # Added injection in parameters
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?b=bb&xss=aa",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?b=bb&sql=aa",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?b=bb&cmdi=aa",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&xss=bb",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&sql=bb",
        "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&cmdi=bb",
        
]
    reqs = r.get_fuzz_reqs("query_params", payloads)
    assert [rr.complete_url() for rr in reqs] == urls



def dirback():
    os.chdir("..")


def dircurrent():
    return os.getcwd()

def dirtest():
    return os.path.join(dircurrent(), "tests")

def sessionstest():
    return os.path.join(dirtest(), "sessions")


def hartest():
    return os.path.join(sessionstest(), "test.har")
def harfwatest():
    return os.path.join(sessionstest(), "fwa-test.har")

# ### HAR
# def test_har_parser():
#     entries = har.get_entries(hartest())
#     faw_entries = har.get_entries(harfwatest())
#     assert len(entries) == 100
#     assert len(faw_entries) == 1998
#     # har = HAR()


def test_helper_values():
    pass
    # headers = ["h1", "h2"]
    # values = [{"h1": "q"}, {"h2" : "d"}]
    # assert helper.get_values()

def test_selectors():
    assert fuzz_all([True, False]) == False
    assert fuzz_all([True, True]) == True
    assert fuzz_all([False, False]) == True