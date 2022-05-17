#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hfinger.analysis import run_tshark, ensure_environment
import sys
from os import path
from json import dump
import pyshark

if __name__ == "__main__":
    # check args
    if len(sys.argv) != 3:
        print(f"Usage: {__file__} <pcap file path> <json output>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    json_file = sys.argv[2]

    if not path.exists(pcap_file):
        print(f"PCAP file does not exist: {pcap_file}")
        sys.exit(2)

    # Load pcap file
    try:
        tshark_exec, tshark_ver = ensure_environment()
        filtered_cap = pyshark.FileCapture(pcap_file, display_filter='http.request.method')
    except Exception as e:
        print(e)
        sys.exit(3)

    result = []

    # get fingerprints
    fingerprints = run_tshark(pcap_file, 5, tshark_exec, tshark_ver)

    # associate fingerprint with packet http info
    for request, fp in zip(filtered_cap, fingerprints):
        del request.http._all_fields[""]

        result.append({
            "raw_request": str(request.http),
            "request": request.http._all_fields,
            "fingerprint": fp["fingerprint"]
        })
    
    # write result to json file
    with open(path.abspath(json_file), 'w') as file:
        dump(result, file)

    print(f"Done. Result written to {json_file} ({len(result)} entries)")
    