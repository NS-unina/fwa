
from mitmproxy import connection
from mitmproxy import version
from mitmproxy.utils import strutils
from mitmproxy.net.http import cookies
from datetime import datetime
from datetime import timezone
import base64


def format_cookies(cookie_list):
    rv = []

    for name, value, attrs in cookie_list:
        cookie_har = {
            "name": name,
            "value": value,
        }

        # HAR only needs some attributes
        for key in ["path", "domain", "comment"]:
            if key in attrs:
                cookie_har[key] = attrs[key]

        # These keys need to be boolean!
        for key in ["httpOnly", "secure"]:
            cookie_har[key] = bool(key in attrs)

        # Expiration time needs to be formatted
        expire_ts = cookies.get_expiration_ts(attrs)
        if expire_ts is not None:
            cookie_har["expires"] = datetime.fromtimestamp(
                expire_ts, timezone.utc
            ).isoformat()

        rv.append(cookie_har)

    return rv


def format_request_cookies(fields):
    return format_cookies(cookies.group_cookies(fields))


def format_response_cookies(fields):
    return format_cookies((c[0], c[1][0], c[1][1]) for c in fields)


def name_value(obj):
    """
    Convert (key, value) pairs to HAR format.
    """
    return [{"name": k, "value": v} for k, v in obj.items()]



def init():
    global SERVERS_SEEN 
    SERVERS_SEEN = set()
    HAR: dict = {}
    HAR.update(
        {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "mitmproxy har_dump",
                    "version": "0.1",
                    "comment": "mitmproxy version %s" % version.MITMPROXY,
                },
                "pages": [],
                "entries": [],
            }
        }
    )
    return HAR

def add_entry(HAR, request, response):
    global SERVERS_SEEN
    # -1 indicates that these values do not apply to current request
    ssl_time = -1
    connect_time = -1

    # Calculate raw timings from timestamps. DNS timings can not be calculated
    # for lack of a way to measure it. The same goes for HAR blocked.
    # mitmproxy will open a server connection as soon as it receives the host
    # and port from the client connection. So, the time spent waiting is actually
    # spent waiting between request.timestamp_end and response.timestamp_start
    # thus it correlates to HAR wait instead.
    timings_raw = {
        "send": request.timestamp_end - request.timestamp_start,
        "receive": response.timestamp_end - response.timestamp_start,
        "wait": response.timestamp_start - request.timestamp_end,
        "connect": connect_time,
        "ssl": ssl_time,
    }

    # HAR timings are integers in ms, so we re-encode the raw timings to that format.
    timings = {k: int(1000 * v) if v != -1 else -1 for k, v in timings_raw.items()}

    # full_time is the sum of all timings.
    # Timings set to -1 will be ignored as per spec.
    full_time = sum(v for v in timings.values() if v > -1)



    started_date_time = datetime.fromtimestamp(
        request.timestamp_start, timezone.utc
    ).isoformat()

    # Response body size and encoding
    response_body_size = (
        len(response.raw_content) if response.raw_content else 0
    )
    response_body_decoded_size = (
        len(response.content) if response.content else 0
    )
    response_body_compression = response_body_decoded_size - response_body_size

    entry = {
        "startedDateTime": started_date_time,
        "time": full_time,
        "request": {
            "method": request.method,
            "url": request.pretty_url,
            "httpVersion": request.http_version,
            "cookies": format_request_cookies(request.list_cookies.fields),
            "headers": name_value(request.list_headers),
            "queryString": name_value(request.query_params or {}),
            "headersSize": len(str(request.list_headers)),
            "bodySize": len(request.content),
        },
        "response": {
            "status": flow.response.status_code,
            "statusText": flow.response.reason,
            "httpVersion": flow.response.http_version,
            "cookies": format_response_cookies(flow.response.cookies.fields),
            "headers": name_value(flow.response.headers),
            "content": {
                "size": response_body_size,
                "compression": response_body_compression,
                "mimeType": flow.response.headers.get("Content-Type", ""),
            },
            "redirectURL": flow.response.headers.get("Location", ""),
            "headersSize": len(str(flow.response.headers)),
            "bodySize": response_body_size,
        },
        "cache": {},
        "timings": timings,
    }

    # Store binary data as base64
    if strutils.is_mostly_bin(flow.response.content):
        entry["response"]["content"]["text"] = base64.b64encode(
            flow.response.content
        ).decode()
        entry["response"]["content"]["encoding"] = "base64"
    else:
        entry["response"]["content"]["text"] = flow.response.get_text(strict=False)

    if flow.request.method in ["POST", "PUT", "PATCH"]:
        params = [
            {"name": a, "value": b}
            for a, b in flow.request.urlencoded_form.items(multi=True)
        ]
        entry["request"]["postData"] = {
            "mimeType": flow.request.headers.get("Content-Type", ""),
            "text": flow.request.get_text(strict=False),
            "params": params,
        }

    if flow.server_conn.connected:
        entry["serverIPAddress"] = str(flow.server_conn.peername[0])

    HAR["log"]["entries"].append(entry)
    return HAR