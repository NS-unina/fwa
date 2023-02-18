
import csv

def get_observations(analyzer_file):
    ret = []
    with open(analyzer_file) as csv_file: 
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                line_count += 1 

            ret.append(row)

    return ret

def oracle(analyzer_file):
    obs = get_observations(analyzer_file)
    print(obs)


