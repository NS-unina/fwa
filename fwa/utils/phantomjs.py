
import os

from fwa.utils import helper


def get_phantomjs_script():
    return os.path.join(helper.home(), ".fwa", "fwa-phantom.js")

def phantom_cmd():
    return "phantomjs {}"
    