import csv
import os
from typing import ByteString
from fwa.oracle import sql
from fwa import oracle_manager
import pytest 

sql_observations_file = os.path.join("tests", "owasp", "data", "observations.csv")
nosql_observations_file = os.path.join("tests", "owasp", "data", "nosql-observations.csv")
observations = oracle_manager.get_observations(sql_observations_file)
anomalous_observations = oracle_manager.get_observations(nosql_observations_file)

def get_obs(url, observations):
    return [o for o in observations if o['url'].strip() == url][0]



def test_owasp_00026():
    o =get_obs("https://localhost:8443/benchmark/sqli-00/BenchmarkTest00026", observations)
    assert sql.oracle(o) is True



@pytest.mark.skip(reason="test after fix")
def test_owasp_00037():
    o =get_obs("https://localhost:8443/benchmark/sqli-00/BenchmarkTest00037", anomalous_observations)
    assert sql.oracle(o) is True
