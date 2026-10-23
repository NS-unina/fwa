import socket
import time


def wait_for_port(host, port, timeout_seconds):
    """Block until a TCP server accepts connections on host:port; raise after timeout_seconds."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError as exc:
            if time.monotonic() > deadline:
                raise RuntimeError("nothing listening on {}:{} after {}s".format(host, port, timeout_seconds)) from exc
            time.sleep(0.1)
