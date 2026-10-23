import re

from fwa.utils.helper import pretty_print_json


# Error messages of the DBMSs behind the benchmarks (MySQL/MariaDB, PostgreSQL,
# SQLite, HSQLDB). The SQL oracle flags one that appears only after fuzzing.
SQL_ERRORS = [
    "You have an error in your SQL syntax",
    "SQL syntax",
    "mysql_fetch",
    "supplied argument is not a valid MySQL",
    "PostgreSQL query failed",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "XPATH syntax error",
    "different number of columns",
    "SQLSTATE[",
    "mysqli_",
    "Warning: mysql_",
    "MariaDB server version",
    "syntax error at or near",
    "unterminated quoted string",
    "invalid input syntax for",
    "PSQLException",
    "pg_query",
    "SQLITE_ERROR",
    "SQLite3::",
    "unrecognized token",
    "same number of result columns",
    "unexpected token",
    "org.hsqldb",
]
# MongoDB driver and server errors.
NOSQL_ERRORS = [
    "MongoError",
    "MongoServerError",
    "MongoDB\\Driver",
]
# Output of 1873*7177, computed by the CMDI and CODE_INJECTION payloads of
# payloads.csv: it appears only if the payload is executed, never by reflection.
COMPUTED_MARKER = str(1873 * 7177)
# First line of /etc/passwd.
PASSWD_MARKER = "root:x:0:0"

KEYWORDS =  [
    "File not found",
    "No such file",
    "uid=",
    "gid=",
    "groups=",
    "Permission denied",
    "whoami",
    "root",
    "echo",
    # SHA of FWA WORD
    "a2cf52ff63502c5869b2813af3f455b6d0c00b0a",
    # "root:",
    "sbin",
    # "sbin:",
    "daemon:",
    "error",
    "exception",
    "illegal",
    "invalid",
    "fail",
    "stack",
    "access",
    "directory",
    "not found",
    "unknown",
    "uid=",
    "ODBC",
    "SQL",
    "SQLSyntaxErrorException",
    "quotation mark",
    "syntax",
    "ORA-",
    "111111",
    COMPUTED_MARKER,
    PASSWD_MARKER,
  ] + SQL_ERRORS + NOSQL_ERRORS


def clean(s):
    return s
    # return re.sub(r'\W+', '', s)

def keywords_search(html, suffix = "_in_response"):
    """
    :param keyword_list: lista di keyword su cui iterare
    :param response: http response
    :param results: dict results
    :return:
    """
    results = {}
    for k in KEYWORDS:
        match = re.search(re.escape(k), html, re.IGNORECASE)
        results["{}{}".format(clean(k), suffix)] = 1 if match is not None else 0

        # if match is not None:
        #     results.update({k: 1})
        # else:
        #     results.update({k: 0})

    return results




def analyze(valid_entry, fuzz_entry):
    resp = []
    valid_response = valid_entry['response']
    valid_size = valid_response['content']['size']
    valid_html = valid_response['content']['text']
    html = fuzz_entry['response']['content']['text']
    # {'string' : 1|0}
    results = keywords_search(html)
    valid_results = keywords_search(valid_html, "_in_valid_response")
    results.update(valid_results)
    return results