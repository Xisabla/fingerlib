#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert data from json converted pcap to json readable by cpp unit tests
"""

from os import path
import json
from docopt import docopt


doc = f"""
{__file__}

Usage:
    {__file__} <input> [--output=file] [--indent]

    input               Input file, converted json from pcap using 'pcap_to_json.py'

Options:
    -h, --help          Show this help message
    -o --output=file    Output file, in which converted data will be stored
    --indent            If set, output will be indented with 4 spaces
"""

def parse_data(entry):
    """Parse data from converted pcap request to data readable by tests

    Args:
        entry (dict): Entry from pcap converted to json

    Returns:
        dict: Dictionary with data readable by tests (uri, method, version,\
headers, payload, fingerprint)
    """
    req = list(filter(None, entry["http_request_raw"].replace("\r\n", "\n").split("\n")))

    (method, uri, version) = req[0].split(" ")

    return {
        "uri": uri,
        "method": method,
        "version": version.replace("HTTP/", ""),
        "headers": req[1:],
        "payload": entry["payload"],
        "fingerprint": entry["fingerprint"]
    }

if __name__ == "__main__":
    arguments = docopt(doc)

    input = arguments["<input>"]
    output = arguments["--output"]
    indent = arguments["--indent"]

    with open(path.abspath(input), 'r', encoding='utf8') as f:
        data = json.load(f)

        res = [ parse_data(d) for d in data ]

        if output:
            with open(path.abspath(output), 'w', encoding='utf8') as out:
                json.dump(res, out, indent=4 if indent else None)

            print(f"Done. Result written to {output} ({len(res)} entries)")
        else:
            print(json.dumps(res, indent=4 if indent else None))
