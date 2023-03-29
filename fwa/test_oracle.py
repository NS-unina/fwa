import csv
import os
from fwa.oracle import sql
from fwa import oracle_manager

sql_observations_file = os.path.join("tests", "owasp", "data", "observations.csv")
observations = oracle_manager.get_observations(sql_observations_file)

def get_obs(url):
    return [o for o in observations if o['url'].strip() == url][0]


def test_owasp_00026():
    o =get_obs("https://localhost:8443/benchmark/sqli-00/BenchmarkTest00026")
    assert sql.oracle(o) is True


