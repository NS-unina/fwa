import sys
from har import *
import csv

def e():
    sys.exit(-1)
def get_test_name(req):
    url = parse_url(req['url'])
    return url.split("/")[-1]

def _find_vulnerable_param(list_params: list):
    ret = 0
    for l in list_params: 
        if ret == 0:
            ret = 1 if l['name'].startswith('BenchmarkTest') else 0
    return ret

def _find_vulnerable_value(list_params: list):
    ret = 0
    for l in list_params: 
        if ret == 0:
            ret = 1 if 'BenchmarkTest' in l['value'] else 0
    return ret

def find_vulnerable_param(req: HarRequest):
    ret = {
        'in_header'             : 0,
        'in_querystring'        : 0,
        'in_cookie'             : 0,
        'in_post'               : 0,
        'in_value_header'       : 0,
        'in_value_querystring'  : 0,
        'in_value_cookie'       : 0,
        'in_value_post'         : 0
    }
    headers     =   req['headers']
    queryString =   req['queryString']
    cookies     =   req['cookies']
    if 'postData' in req.keys():
        postData    =   req['postData']['params']
        ret['in_post'] = _find_vulnerable_param(postData)
        ret['in_value_post'] = _find_vulnerable_value(postData)

    ret['in_header'] = _find_vulnerable_param(headers)

    ret['in_querystring'] = _find_vulnerable_param(queryString)
    ret['in_value_querystring'] = _find_vulnerable_value(queryString)

    ret['in_cookie'] = _find_vulnerable_param(cookies)
    ret['in_value_cookie'] = _find_vulnerable_value(cookies)
    if not ret['in_cookie']:  
        ret['in_value_header'] = _find_vulnerable_value(headers)

    return ret

def only_one(v):
    return sum(list([l for l in v.values() if isinstance(l, int)])) == 1

# def test(v):
#     if not only_one(v):
#         print(v)

if __name__ == '__main__' :
    har_entries : list[HarEntry]= get_entries(sys.argv[1]) 
    END = 12
    index = 0
    arr = []
    for h in har_entries: 
        req = h['request']
        ret = find_vulnerable_param(req)
        name = get_test_name(req)
        ret['name'] = name
        method = req['method']
        ret['method'] = method
        arr.append(ret)

    names = arr[0].keys()

    with open('owasp_har_characteristics.csv', 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=names)
        writer.writeheader()
        writer.writerows(arr)

    
