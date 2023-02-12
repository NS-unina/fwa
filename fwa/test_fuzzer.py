from fwa.fuzzer import Request

def req():
    url = "https://localhost:8443/benchmark/cmdi-02/BenchmarkTest02242?a=aa&b=bb" 
    method = "POST" 
    cookies = [] 
    headers = [{'name': 'User-Agent', 'value': 'Apache-HttpClient/5.1.3 (Java/17.0.5)'}, {'name': 'Accept-Encoding', 'value': 'gzip, deflate, br'}, {'name': 'Accept', 'value': '*/*'}, {'name': 'Connection', 'value': 'keep-alive'}, {'name': 'Content-Type', 'value': 'application/x-www-form-urlencoded'}, {'name': 'Content-Length', 'value': '25'}, {'name': 'Host', 'value': 'localhost:8443'}]
    r = Request(url, method, cookies, headers)
    return r

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
]
    reqs = r.get_fuzz_reqs("query_params", payloads)
    assert [rr.complete_url() for rr in reqs] == urls