from logging import info
from fwa.utils import helper
from fwa.utils.net import wait_for_port
import os
from mitmproxy import ctx

# This module starts a static webserver useful for several purposes

HTTP_SERVER_PORT = 18081

def get_webserver_path():
    return os.path.join(helper.home(), ".fwa", "static-webserver")

def web_cmd():
    return "python3 -m http.server  {} -d {}".format(HTTP_SERVER_PORT, get_webserver_path())

def start_webserver():
    info("Start fwa webserver")
    os.system(web_cmd() + " &")
    # The XSS analyzer opens pages from this server: do not start analyzing before it listens.
    wait_for_port("127.0.0.1", HTTP_SERVER_PORT, 30)

def stop_webserver():
    info("Stop fwa webserver")
    os.system("kill `ps aux | grep static-webserver | grep -v grep | awk '{print $2}' | xargs`")

