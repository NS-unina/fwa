"""Parameters of JSON bodies, XML bodies and URL paths.

- JSON body: the parameters are the top-level keys of a JSON object (any other
  JSON body has none). A payload that is itself a JSON object or array (e.g.
  {"$ne":null}) is set as that JSON value; any other payload as a JSON string.
- XML body: the parameters are the leaf elements whose tag is unique in the
  body, named by tag (repeated tags are not addressable and stay unchanged); a
  payload is the element text, XML-escaped when serialized.
- URL path: the parameters are the non-empty segments, named by their index in
  ``path.split("/")``; a payload is percent-encoded as one segment.
"""

import json
import xml.etree.ElementTree as ET
from urllib.parse import quote, unquote, urlparse


def json_value(payload):
    try:
        value = json.loads(payload)
    except ValueError:
        return payload
    return value if isinstance(value, (dict, list)) else payload


def json_params(text):
    """[{'name', 'value'}] of a JSON body; non-string values as compact JSON."""
    value = json.loads(text)
    if not isinstance(value, dict):
        return []
    return [{'name': key, 'value': item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))}
            for key, item in value.items()]


def _leaves(root):
    leaves = [element for element in root.iter() if len(element) == 0]
    tags = [element.tag for element in leaves]
    return [element for element in leaves if tags.count(element.tag) == 1]


def xml_params(text):
    """Leaf element tag -> text of an XML body."""
    return {element.tag: element.text or '' for element in _leaves(ET.fromstring(text))}


def xml_with_values(text, values):
    """The XML body ``text`` with the leaf elements of ``values`` set to their value."""
    root = ET.fromstring(text)
    for element in _leaves(root):
        if element.tag in values:
            element.text = values[element.tag]
    declaration = text[:text.index("?>") + 2] if text.lstrip().startswith("<?xml") else ""
    return declaration + ET.tostring(root, encoding="unicode")


def path_params(url):
    """Segment index -> segment (percent-encoded, as in the URL) of the URL path."""
    return {str(index): segment for index, segment in enumerate(urlparse(url).path.split('/')) if segment}


def path_segment(payload):
    return quote(payload, safe='')


def path_values(url):
    """[{'name', 'value'}] of the URL path, segments decoded."""
    return [{'name': index, 'value': unquote(segment)} for index, segment in path_params(url).items()]
