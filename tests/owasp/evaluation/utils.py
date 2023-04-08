
import sys
from turtle import pd
from typing import TypedDict


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

COL_TESTNAME = "# test name"
COL_CAT = " category"
COL_REAL = " real vulnerability"
df_owasp = pd.read_csv('expectedresults-1.2.csv')

def get_cat(category):
    return df_owasp[df_owasp[COL_CAT] == category]


"""
 OWASP CATS: 
    pathtraver
"""
def usage():
     print("[+] usage: {} owasp_cat fwa_cat".format(sys.argv[0]))
     exit(-1)