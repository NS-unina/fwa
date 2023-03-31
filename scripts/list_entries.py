import sys
from har import *


if __name__ == '__main__' :
    har_entries : list[HarEntry]= get_entries(sys.argv[1]) 
    print("The file contains {} entries".format(len(har_entries)))
