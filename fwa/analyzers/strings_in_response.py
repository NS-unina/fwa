import re

from fwa.utils.helper import pretty_print_json


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
    "111111"
  ]


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