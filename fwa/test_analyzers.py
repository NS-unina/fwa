from fwa.analyzer_manager import get_fuzz_entries
from fwa.analyzers import time_delay
# from fwa.oracle import xss
from fwa.oracle import sql
from os.path import join
from fwa.main import oracle

from fwa.utils import har, payloads

sqli_payload = join("tests", "owasp", "payloads", "sqli.csv")
simple_file = join("tests", "sessions", "time-based", "swigger-sqli.har")
fuzz_file = join("tests", "sessions", "owasp", "fwa-owasp-sqli.har")

def test_sqli():
    ploads = payloads.load(sqli_payload)
    fuzz_entries = har.get_fuzz_entries(fuzz_file, ploads)
    # print(fuzz_entries)

def test_time_delay():
    ploads = payloads.load(sqli_payload)
    fuzz_entries = har.get_fuzz_entries(fuzz_file, ploads)
    pass
    # print(fuzz_entries)
#     valid_entry = har.get_entries(simple_file)[0]
#     f = fuzz_entries[0]
#     f2 = fuzz_entries[1]
#     assert time_delay.analyze(valid_entry, f)['time_delay'] is True
#     assert time_delay.analyze(valid_entry, f2)['time_delay'] is False



def xss_obs(pt, p, refl):
    return {
        'payload' : p, 
        'payload_type' : pt, 
        'payload_reflected' : refl
    }

# def test_oracle():
#     # XSS 
#     assert xss.oracle(xss_obs('XSS', '<script>alert(1)</script>', 1))
#     assert xss.oracle(xss_obs('SQL', '<script>alert(1)</script>', 1)) is False
#     assert xss.oracle(xss_obs('SQL', '<script>alert(1)</script>', 1)) is False
#     assert xss.oracle(xss_obs('XSS', '<script>alert(1)</script>', 0)) is False


    # SQL 
    assert sql.oracle({
        'payload_type': 'SQL',
        'content_length' : 1
    }) is True 
    assert sql.oracle({
        'payload_type': 'SQL',
        'time_delay' : 1
    }) is True 