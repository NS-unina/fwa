from datetime import datetime, timezone
import functools
import json
import os
from pathlib import Path
import sys
import time
import logging
from fwa.utils import mitm, webserver

# LOGGIN


class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    # format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    # format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format ='%(asctime)s %(levelname)-8s %(message)s '
    datefmt='%Y-%m-%d %H:%M:%S'

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)



def create_query_string(data: dict):
    ret = ""
    for k, d in data.items():
        ret = ret + "{}={}&".format(k, d)
    return ret[:-1]

def setup_custom_logger(name):
    formatter = CustomFormatter()
    # logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                #   datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.FileHandler('log.txt', mode='w')
    handler.setFormatter(formatter)

    # handler.setFormatter(formatter)
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.addHandler(screen_handler)
    return logger



logger = setup_custom_logger("fwa")

def info(msg):
    logger.info(msg)
def dbg(msg):
    logger.debug(msg)
def warn(msg):
    logger.warning(msg)
def err(msg):
    logger.error(msg)
    mitm.stop_record()
    sys.exit(-1)


# FWA UTILS
FWA_PREFIX = "fwa-"

def fwa_package_path():
    return os.path.dirname(os.path.dirname(__file__))

def fwa_default_analyzers_path():
    return os.path.join(fwa_package_path(), "analyzers")

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
    # Static web-server for listening
    os.makedirs(webserver.get_webserver_path(), 0o775, True)
    # os.makedirs(os.path.join(home(), ".fwa", "fuzz-sessions"), 0o775, True)

    
def fwa_list_sessions():
    """Returns the list of sessions, remove those starting by fwa- as they are generated by fwa
    Returns:
        list: The list of recorded sessions
    """
    return [s for s in get_files(fwa_session_path()) if not s.startswith(FWA_PREFIX)]


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

def get_project_root():
                            # Returns "utils"
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fuzz_all(selectors: list):
    """Fuzz all if all are selected
    Args:
        selectors (list(bool)): The list of boolean
    """
    return not functools.reduce(lambda a,b : a ^ b, selectors)


def pretty_print_json(d):
    print(json.dumps(d, indent=4))



def debug_print(msg):
    print(str(msg))
