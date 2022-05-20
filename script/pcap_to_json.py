#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert data from provided pcap to json format
"""

import sys
from os import path
import subprocess
import json
from docopt import docopt
from hfinger.analysis import run_tshark, ensure_environment

doc = f"""
{__file__}

Usage:
    {__file__} <input> [--output=file] [--indent]

    input               Input file, pcap format

Options:
    -h, --help          Show this help message
    -o --output=file    Output file, in which converted data will be stored
    --indent            If set, output will be indented with 4 spaces
"""

def dict_no_raw(d):
    """Remove all fields containing raw data from dictionary

    Args:
        d (dict): Dictionary to be cleaned

    Returns:
        dict: Dictionary without raw data
    """
    n = {}
    
    for k,v in d.items():
        if isinstance(v, dict):
            n[k] = dict_no_raw(v)
        elif not 'raw' in k:
            n[k] = v
    
    return n

def parse_data(p, fp):
    # Retrieve http request
    http = p["_source"]["layers"]["http"]
    http_raw = p["_source"]["layers"]["http_raw"][0]

    # Retrieve payload
    frame_raw = p["_source"]["layers"]["frame_raw"][0]
    delim = "0d0a0d0a" if "0d0a0d0a" in frame_raw else "0d0a"
    payload_raw = frame_raw[frame_raw.find(delim) + len(delim) : ]
    payload = bytes.fromhex(payload_raw).decode()
    
    # Remove all '_raw' fields
    http = dict_no_raw(http)
    
    return {
        "http_request": http,
        "http_request_raw": str(bytes.fromhex(http_raw).decode()),
        "payload": str(payload),
        "fingerprint": fp["fingerprint"]
    }

if __name__ == "__main__":
    arguments = docopt(doc)

    input = arguments["<input>"]
    output = arguments["--output"]
    indent = arguments["--indent"]

    if not path.exists(input):
        print("Input file does not exist")
        sys.exit(1)


    # Load pcap file
    try:
        texec, tver = ensure_environment()

        # Use tshark to parse pcap file and load at json format
        res = subprocess.run([
            texec,
            "-T",
            "json",
            "-x",
            "-Yhttp.request and tcp and not icmp",
            "-r",
            input
            ], capture_output=True, check=True)

        pcap = json.loads(res.stdout.decode("utf-8"))
    except Exception as e:
        print(str(e))
        sys.exit(3)

    fingerprints = run_tshark(input, 5, texec, tver)
    res = [ parse_data(p, fp) for p, fp in zip(pcap, fingerprints) ]
    
    if output:
        with open(path.abspath(output), 'w', encoding='utf8') as out:
            json.dump(res, out, indent=4 if indent else None)

        print(f"Done. Result written to {output} ({len(res)} entries)")
    else:
        print(json.dumps(res, indent=4 if indent else None))
