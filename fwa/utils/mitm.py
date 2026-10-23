from logging import info
from fwa.utils import helper
import os
from mitmproxy import ctx



def recorder_script():
    return os.path.join(helper.get_project_root(), "recorder.py")

def mitm_cmd(url, session_name, quiet = False, entries = ""):
    cmd = "mitmdump -s {} {} -k --set validate_inbound_headers=false --set url={}  --set session={}".format(recorder_script(), "-q" if quiet else "", url, session_name)
    if entries:
        cmd += " --set entries={}".format(entries)
    return cmd

def start_record(url, session_name, quiet, background, entries = ""):
    """Start the recording proxy; with ``entries``, it also appends each recorded entry to that file."""
    info("Start fwa record")
    if background:
        print(mitm_cmd(url, session_name, quiet, entries) + " &")
        os.system(mitm_cmd(url, session_name, quiet, entries) + " &")

    else:
        os.system(mitm_cmd(url, session_name, quiet, entries))


def stop_record():
    info("Stop fwa record")
    # Kill all mitmdump sessions. This shoukd be refactored
    os.system("kill `ps aux | grep [m]itmdump | awk '{print $2}' | xargs`")
