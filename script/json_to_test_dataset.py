#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert data from json converted pcap to json readable by cpp unit tests
"""

from ast import arg
from multiprocessing.sharedctypes import Value
from os import path
import json
from docopt import docopt


doc = f"""
{__file__}

Usage:
    {__file__} <input> [--output=file] [--indent] [--filter=string] [--tags=string]

    input               Input file, converted json from pcap using 'pcap_to_json.py'
    tags                string, can be a list of element "first,second"

Options:
    -h, --help          Show this help message
    -o --output=file    Output file, in which converted data will be stored
    --indent            If set, output will be indented with 4 spaces
    --filter=string     If the filter is not on the request, the request is ignored
    --tags=string       tag for the filtered fingerprint 
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
    filter_value = arguments["--filter"]
    tags = arguments["--tags"].split(',')


    with open(path.abspath(input), 'r', encoding='utf8') as f:
        data = json.load(f)

        res = [ parse_data(d) for d in data ]

        # find the request with this string inside
        valid_req_lit = []
       
        for req in res:
            for v in req.values():
                if filter_value in v:             
                    valid_req_lit.append(req.copy())
                    valid_req_lit[-1]["tags"] = tags
        
        
        if output:
            with open(path.abspath(output), 'w', encoding='utf8') as out:
                json.dump(valid_req_lit, out, indent=4 if indent else None)

            print(f"Done. Result written to {output} ({len(res)} entries)")
        else:
            print(json.dumps(valid_req_lit, indent=4 if indent else None))
