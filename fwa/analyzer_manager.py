import importlib
import os
from fwa.utils import helper

def _run_analyzer(filename, ):
        module_name = os.path.splitext(filename)[0]
        module = importlib.import_module(module_name)
        if hasattr(module, "analyze"):
            module.analyze()



def run(session_name, fuzz_session_name, analyzers_path, results_file):
    """ Run all the analyzers, get results and write in the output file

    Args:
        analyzers_path (str): The path
    """
    for filename in os.listdir(analyzers_path):
        if filename.endswith(".py"):
            helper.info("Run {}".format(filename))

