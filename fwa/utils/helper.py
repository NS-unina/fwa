from datetime import datetime, timezone
import os
from pathlib import Path
import time


def get_files(path):
    files = []
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            files.append(file)
    return [f.replace(".har", "") for f in files]

def home():
     return str(Path.home())
def fwa_path():
    return os.path.join(home(), ".fwa")

def fwa_session_path():
    return os.path.join(fwa_path(), "sessions")

def fwa_session(session_name):
    return os.path.join(fwa_session_path(), "{}.har".format(session_name))

def fwa_init():
    os.makedirs(os.path.join(home(), ".fwa", "sessions"), 0o775, True)
    os.makedirs(os.path.join(home(), ".fwa", "fuzz-sessions"), 0o775, True)

    
def fwa_list_sessions():
    return get_files(fwa_session_path())


def to_dict(l: list):
    """Generate a dictionary from an array

    Args:
        l (list): A list

    Returns:
        dict: A dictionary
    """
    ret = {}
    for i in l:
        ret[i['name']] = i['value']
    return ret

# Time functions
def timestamp():
    """Get the current timestamp in seconds
    """

    now = int( time.time() )
    return now


# 2023-02-12T07:27:04+00:00
def iso_time_from_timestamp(timestamp):
    return datetime.fromtimestamp(
        timestamp, timezone.utc
    ).isoformat()



class ProgressBar:

    def __init__(self, total, decimals = 1, prefix='Progress:', suffix='Complete', length=50):
        self.total  = total
        self.decimals = 1
        self.prefix = prefix 
        self.suffix = suffix 
        self.length = length
        self.fill='█'
        self.print_end = "\r"

    def print(self, iteration):
        """
        Call in a loop to create terminal progress bar
        @params:
            iteration   - Required  : current iteration (Int)
            total       - Required  : total iterations (Int)
            prefix      - Optional  : prefix string (Str)
            suffix      - Optional  : suffix string (Str)
            decimals    - Optional  : positive number of decimals in percent complete (Int)
            length      - Optional  : character length of bar (Int)
            fill        - Optional  : bar fill character (Str)
            printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
        """
        percent = ("{0:." + str(self.decimals) + "f}").format(100 * (iteration / float(self.total)))
        filledLength = int(self.length * iteration // self.total)
        bar = self.fill * filledLength + '-' * (self.length - filledLength)
        print(f'\r{self.prefix} |{bar}| {percent}% {self.suffix}', end = self.print_end)
        # Print New Line on Complete
        if iteration == self.total:
            print()

