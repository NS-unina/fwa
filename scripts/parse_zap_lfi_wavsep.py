import sys
from har import *

def _write_file(content, dst):
    with open(dst, 'w') as f:
        f.writelines([c + '\n' for c in content])

def get_user_input(query_string):
    for i in query_string:
        if 'name' in i and i['name'] == 'userinput': 
            return i['value']
    return None

valid_payloads = ['1234', 'david', 'textvalue', 'dummy.html', ' ', 'ZAP', '', '\n']
if __name__ == '__main__' :
    payloads = []
    har_entries : list[HarEntry] = get_entries(sys.argv[1])

    payloads = []
    for h in har_entries:
        req = h['request']
        # print(req['url'])
        query_string = req['queryString']
        for q in query_string:
            if 'name' in q:
                if q['value']:
                    payloads.append(q['value'])


        
        # pass
        # user_input = get_user_input(query_string)
        # if user_input:
        #     payloads.append(user_input)

    payloads = [p for p in payloads if p not in valid_payloads]

    payloads = sorted(set(payloads))
    _write_file(payloads, 'zap-lfi.txt')


    