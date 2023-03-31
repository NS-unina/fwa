import csv
import sys
from typing import TypedDict
import pandas as pd



def e(msg = ""):
    print("[-] {}".format(str(msg)))
    sys.exit(-1)


class Stats(TypedDict):
     accuracy: float
     precision: float 
     recall: float
     f1 : float 
     specificity : float

class Cases(TypedDict):
     true_positive_cases: list
     true_negative_cases: list
     false_positive_cases: list
     false_negative_cases: list

class ConfusionMatrix:
    def __init__(self, tp, tn, fp, fn):
        self.true_positive = tp 
        self.true_negative = tn 
        self.false_positive = fp 
        self.false_negative = fn

    def stats(self):
        accuracy = (self.true_positive + self.true_negative)/ float (self.true_positive + self.true_negative + self.false_positive + self.false_negative)
        precision = self.true_positive/(self.true_positive + self.false_positive)
        recall = self.true_positive/(self.true_positive + self.false_negative)
        f1 = 2 * (recall * precision)/(recall + precision)
        specificity = self.true_negative/(self.true_negative + self.false_positive)
        ret_stats : Stats = {
             'accuracy' : accuracy, 
             'precision' : precision,
             'f1' : f1,
             'recall' : recall,
             'specificity' : specificity
        }
        return ret_stats 

# ['# test name', ' category', ' real vulnerability', ' cwe', ' Benchmark version: 1.2', ' 2016-06-1']
COL_TESTNAME = "# test name"
COL_CAT = " category"
COL_REAL = " real vulnerability"
df_owasp = pd.read_csv('expectedresults-1.2.csv')
df_fwa = pd.read_csv('vulnerabilities.csv')

def get_cat(category):
    return df_owasp[df_owasp[COL_CAT] == category]


def get_true_cases(category):
    df_cat = get_cat(category)
    return df_cat[df_cat[COL_REAL] == True]

def get_false_cases(category):
    df_cat = get_cat(category)
    return df_cat[df_cat[COL_REAL] == False]


def get_fwa_cat(cat):
    return df_fwa[df_fwa['vulnerability'] == cat]


def get_test_case(r):
    return r['url'].rsplit('/', 1)[1]

def find_fwa_related_to_test_case(cat, test_case):
    # Find fwa entries related with the given test case
    ret = []
    df_cat = get_fwa_cat(cat)
    for i, r in df_cat.iterrows():
        if get_test_case(r) == test_case:
            ret.append(r)

    return ret

def is_vulnerability(related_to_test_case):
        for r in related_to_test_case:
            if r['is_present']:
                return True
        return False




def _get_stats(cat, fwa_cat):
    no_tp = 0 
    no_tn = 0 
    no_fp = 0
    no_fn = 0
    true_positive_cases: list = []
    true_negative_cases: list = []
    false_positive_cases: list = []
    false_negative_cases: list = []
    # Navigate true positive
    owasp_sql_true = get_true_cases(cat)
    owasp_sql_false = get_false_cases(cat)


    fwa_sql = get_fwa_cat(fwa_cat)
    for i,r in owasp_sql_true.iterrows():
        test_name = r[COL_TESTNAME]
        related_to_test_case = find_fwa_related_to_test_case(fwa_cat, test_name)
        if is_vulnerability(related_to_test_case):
                print("[+] Correct vulnerability for {}".format(test_name))
                no_tp = no_tp + 1
                true_positive_cases.append(test_name)
        else:
            print("[-] Incorrect vulnerability for {}".format(test_name))
            no_fn = no_fn + 1
            false_negative_cases.append(test_name)
            

    for i,r in owasp_sql_false.iterrows():
        # If properly classified with 
        test_name = r[COL_TESTNAME]
        related_to_test_case = find_fwa_related_to_test_case(fwa_cat, test_name)
        # When is false is ok
        if not is_vulnerability(related_to_test_case):
                print("[+] Correct non vulnerability for {}".format(test_name))
                no_tn = no_tn + 1
                true_negative_cases.append(test_name)
        else:
                print("[+] Incorrect non vulnerability for {}".format(test_name))
                no_fp = no_fp + 1
                false_positive_cases.append(test_name)
    cm = ConfusionMatrix(no_tp, no_tn, no_fp, no_fn)
    stats = cm.stats()
    stats['type'] = cat
    cases : Cases = {}
    cases['true_positive_cases'] = true_positive_cases
    cases['true_negative_cases'] = true_negative_cases
    cases['false_positive_cases'] = false_positive_cases
    cases['false_negative_cases'] = false_negative_cases

    return stats, cases

def get_sql_stats():
    return _get_stats('sqli', 'sql')

def get_xss_stats():
    return _get_stats('xss', 'xss')



def _append(s, arr, index):
    append_str = ""
    if len(arr) > index:
        append_str = arr[index]
    return s + append_str

def prepare_lines_for_test_cases(cases: Cases):
    to_write = "true_positive, true_negative, false_positive, false_negative \n"
    lengths = [ len(cases['true_positive_cases']), 
                len(cases['false_positive_cases']),
                len(cases['true_negative_cases']),
                len(cases['false_negative_cases'])
    ]
    max_cases = max(lengths)
    for i in range(0, max_cases):
        to_write = _append(to_write, cases['true_positive_cases'], i) + ","
        to_write = _append(to_write, cases['true_negative_cases'], i) + ","
        to_write = _append(to_write, cases['false_positive_cases'], i) + ","
        to_write = _append(to_write, cases['false_negative_cases'], i) + "\n"
    # cases['false_negative_cases']
    with open('cases.csv', 'w') as f:
        f.write("sep=,\n")
        f.writelines(to_write)




if __name__ == '__main__':
    # column_headers = df_owasp.columns.values.tolist()
    stats, cases = get_xss_stats()
    prepare_lines_for_test_cases(cases)

    with open('stats.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=stats.keys())
        writer.writeheader()
        writer.writerow(stats)