#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from os import path
import subprocess
import json
from hfinger.analysis import run_tshark, ensure_environment


def dict_no_raw(d):
    n = {}
    
    for k,v in d.items():
        if isinstance(v, dict):
            n[k] = dict_no_raw(v)
        elif not 'raw' in k:
            n[k] = v
    
    return n

if __name__ == "__main__":
    # Check arguments
    if len(sys.argv) < 3:
        print(f"Usage: {__file__} <pcap file path> <json output> [--indent]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    json_file = sys.argv[2]

    INDENT = "--indent" in sys.argv

    if not path.exists(pcap_file):
        print(f"PCAP file does not exist: {pcap_file}")
        sys.exit(2)

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
            pcap_file
            ], capture_output=True, check=True)

        pcap = json.loads(res.stdout.decode("utf-8"))
    except Exception as e:
        print(str(e))
        sys.exit(3)

    result = []

    fingerprints = run_tshark(pcap_file, 5, texec, tver)

    for p, fp in zip(pcap, fingerprints):
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

        # Forge json
        result.append({
            "http_request": http,
            "http_request_raw": str(bytes.fromhex(http_raw).decode()),
            "payload": str(payload),
            "fingerprint": fp["fingerprint"]
        })

    # Write result to json file
    with open(path.abspath(json_file), 'w', encoding='utf8') as file:
        if INDENT:
            json.dump(result, file, indent=4)
        else:
            json.dump(result, file)

    print(f"Done. Result written to {json_file} ({len(result)} entries)")
