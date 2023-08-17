from har import *

def read_list():
    with open('list.txt') as f: 
        data = f.readlines()
    return [d.replace("\n", "") for d in data]

if __name__ == '__main__' :
    har_file = "owasp-sqli.har"
    har_entries : list[HarEntry]= get_entries(har_file) 

    list_new : list[HarEntry] = []
    for l in read_list():
        uh = get_entries_by_content(l, har_entries)
        if len(uh) > 0:
            list_new = list_new + uh
    change_entries(har_file, list_new)

