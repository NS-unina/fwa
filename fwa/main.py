import os
from fwa.utils.helper import fwa_init, fwa_list_sessions, fwa_session
from fwa.utils import mitm
import typer
import fwa.fuzzer as fuzzer



## Con poetry 
typer_app = typer.Typer(add_completion=False, context_settings={"help_option_names": ["-h", "--help"]})


@typer_app.command()
def record(session_name: str, quiet: bool = typer.Option(False, help="Quiet mode"), background : bool = typer.Option(False, help="If mitmdump should run in background")):
    """Run the listener
    """
    fwa_init()
    mitm.start_record(session_name, quiet, background)

    # -s repeater.py  -k -q)

@typer_app.command()
def list():
    print(fwa_list_sessions())

@typer_app.command()
def replay(session_name: str, proxy: str = typer.Option("", help="proxy (<host>:<port>)")):
    """Resend a session

    Args:
        session_name (str): The session name
        proxy (str, optional): The proxy in form http://<host>:<port>
    """
    fuzzer.send_from_har(session_name, proxy)

@typer_app.command()
def stop_record():
    mitm.stop_record()
    pass



@typer_app.command()
def fuzz(session_name: str, payload_file: str = typer.Argument("payloads.csv", help="The csv payload in the form <payload>,<payload_type>")):
    fuzzer.fuzz_from_har(session_name, payload_file)



def run():
    typer_app()
    