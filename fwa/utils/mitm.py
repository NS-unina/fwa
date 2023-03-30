from logging import info
from fwa.utils import helper
import os
from mitmproxy import ctx



def recorder_script():
    return os.path.join(helper.get_project_root(), "recorder.py")

def mitm_cmd(url, session_name, quiet = False):
    return "mitmdump -s {} {} -k --set url={} --set session={}".format(recorder_script(), "-q" if quiet else "", url, session_name)

def start_record(url, session_name, quiet, background):
    info("Start fwa record")
    if background:
        print(mitm_cmd(url, session_name, quiet) + " &")
        os.system(mitm_cmd(url, session_name, quiet) + " &")

    else:
        os.system(mitm_cmd(url, session_name, quiet))


def stop_record():
    info("Stop fwa record")
    # Kill all mitmdump sessions. This shoukd be refactored
    os.system("kill `ps aux | grep [m]itmdump | awk '{print $2}' | xargs`")
