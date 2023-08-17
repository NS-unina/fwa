import requests
url="https://localhost:8443/benchmark/sqli-00/BenchmarkTest00037"
payload = "answer=&BenchmarkTest00037=bar&%27=BenchmarkTest00037"
def default_headers():
    return {"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0"}
headers = default_headers()
headers['Content-Type'] = "application/x-www-form-urlencoded"

resp = requests.post(url, proxies = {"http" : "127.0.0.1:8081", "https" : "127.0.0.1:8081"}, verify = False, headers = headers, allow_redirects=False, data=payload)