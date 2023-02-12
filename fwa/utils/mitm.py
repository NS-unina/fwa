import os
from mitmproxy import ctx
import logging

logger = logging.getLogger('fwa')
logger.setLevel(logging.INFO)


def info(msg):
    logger.info(msg) 


def recorder_script():
    return os.path.join("fwa", "recorder.py")

def mitm_cmd(session_name, quiet = False):
    return "mitmdump -s {} {} -k --set session={}".format(recorder_script(), "-q" if quiet else "", session_name)

def start_record(session_name, quiet, background):
    info("Start fwa record")
    if background:
        os.system(mitm_cmd(session_name, quiet) + " &")

    else:
        os.system(mitm_cmd(session_name, quiet))


def stop_record():
    info("Stop fwa record")
    # Kill all mitmdump sessions. This shoukd be refactored
    os.system("kill `ps aux | grep [m]itmdump | awk '{print $2}' | xargs`")
