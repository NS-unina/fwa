import os
from pathlib import Path
import subprocess

xss_phantomjs_script= """
var webPage = require('webpage');
var page = webPage.create();

page.onAlert = function(msg) {
    if (msg == "1") {
        console.log("VULNERABLE")
    }
}

page.open('http://127.0.0.1:18080/xss.html', function(status) {
    phantom.exit()

})
"""
def home():
     return str(Path.home())

def _phantom_alert_path():
    return os.path.join(home(), ".fwa", "alert-detection.js")
def setup():
    print("Create the phantomjs script")
    _write_file(xss_phantomjs_script,  _phantom_alert_path())



def webfile_path():
    return os.path.join(home(), ".fwa", "static-webserver", "xss.html")

def _write_file(content, dst):
    with open(dst, 'w') as f:
        f.write(content)



def analyze(valid_entry, fuzz_entry):
    html_content = fuzz_entry['response']['content']['text']
    _write_file(html_content, webfile_path())
    alert_executed = 0
    if "alert" in html_content: 
        print("Analyze")
        print(html_content)
        data = subprocess.check_output(['phantomjs', _phantom_alert_path()]).decode('utf-8')
        if data == "VULNERABLE\n":
            print("[+]Alert executed!")
            alert_executed = 1




    return {
        'alert_executed' : alert_executed
    }