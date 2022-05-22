#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Convert data from pcap to json format

Usage:
    convert.py <pcap> [--help] [-o <file>] [-b] [-c] [-F] [-f <filter>]
        [-v] [--tags=<tags>]
    convert.py (-h | --help)
    convert.py --version

    Convert data from pcap to json format, using specified filter(s).

    Filters will help limiting the data to be converted. They aim to help targeting
        data related to a specific attack and tagging them.

    If no output file is specified, output will be printed to stdout.

Options:
    -h --help           Show this screen.
    -v --verbose        Show more information.
    -o --output=<file>  Output file, in which converted data will be stored.
    -c --cpp            Format output for cpp tests.
    -b --beautify       If set, output will be indented with 4 spaces.
    -F --force          Erase existing files
    -f --filter=<filter[,filter2,filter3,...]>  Filter(s) to be used.
        Available filters: {{ filters }}
    --tags=<tags>       Tags to be added to each entry. Some filters add tag by default.
"""

import os
import sys
import json
from os import path
from importlib import import_module
from subprocess import run
from docopt import docopt
from hfinger.analysis import run_tshark, ensure_environment
from filters.common import tag

SCRIPT_DIR = path.join(path.dirname(path.realpath(__file__)))


# Args

def parse_arg_list(arg, default=None):
    """Parse argument list

    Args:
        arg (string): argument to parse
        default (any, optional): Default value to return. Defaults to None.

    Returns:
        list: Parsed list
    """
    if not arg:
        return default if default else []

    return [
        value.strip()
        for value in arg.split(',')
    ]


# Data operations

def get_methods(parent, sub, method_name):
    """Search for modules in a directory and seek for the given method

    Args:
        parent (string): Parent directory
        sub (string): Sub directory, in which the modules are located
        method_name (string): Name of the method to seek in modules

    Returns:
        dict(string, function): Found methods from modules
    """
    directory = path.join(parent, sub)

    files = [f[:-3]
             for f in os.listdir(directory) if f.endswith('.py') and f != 'common.py']
    modules = [import_module(f'{sub}.{f}') for f in files]
    methods = {
        m.__name__.replace(f'{sub}.', ''): getattr(m, method_name)
        for m in modules
    }

    return methods


def apply_filters(data, filters):
    """Apply filters to data

    Args:
        data (list): data read from pcap
        filters (list(string; function)): Filters to apply to the data

    Returns:
        list: Filtered data
    """
    if not filters:
        return data

    for filter in filters:
        data = filter[1](data)

    return data


def tag_data(data, tagname):
    """Apply tag to data

    Args:
        data (list): data read from pcap (can be filtered)
        tagname (string): Tag to apply

    Returns:
        list: Tagged data
    """
    return [tag(entry, tagname) for entry in data]


# Pcap

def read_pcap(file, hfinger_mode=5):
    """Read pcap file and return data. Also compute the fingerprints of each entry.

    Args:
        file (string): Path to pcap file
        hfinger_mode (int, optional): Mode to use in hfinger to compute fingerprint.
            Defaults to 5.

    Returns:
        list: Read data from pcap file
    """
    try:
        texec, tver = ensure_environment()

        res = run([
            texec,
            '-T',
            'json',
            '-x',
            '-Yhttp.request and tcp and not icmp',
            '-r',
            file
        ], capture_output=True, check=True)

        if res.returncode != 0:
            print(f'Unable to read pcap file "{file}"')
            sys.exit(2)

        pcap = json.loads(res.stdout.decode('utf-8'))
        fingerprints = run_tshark(file, hfinger_mode, texec, tver)

        return (pcap, fingerprints)
    except Exception as err:
        print(f'Unable to read pcap file "{file}": {str(err)}')
        sys.exit(2)


def get_request(entry):
    """Retrieve and parse request from raw pcap data

    Args:
        entry (dict): Entry read from pcap file

    Returns:
        dict: Parsed data from the entry
    """
    # Retrieve http request
    http_raw = entry["_source"]["layers"]["http_raw"][0]
    http_req_raw = str(bytes.fromhex(http_raw).decode())
    http_req_parsed = list(
        filter(
            None,
            http_req_raw.replace(
                "\r\n",
                "\n").split("\n")))

    # Retrieve payload
    frame_raw = entry["_source"]["layers"]["frame_raw"][0]
    delim = "0d0a0d0a" if "0d0a0d0a" in frame_raw else "0d0a"
    payload_raw = frame_raw[frame_raw.find(delim) + len(delim):]
    payload = bytes.fromhex(payload_raw).decode()

    return {
        "raw": http_req_raw,
        "parsed": http_req_parsed,
        "payload": str(payload)
    }


# Output

def format_entry_cpp(entry):
    """Format data for cpp tests

    Args:
        entry (dict): Read data entry from pcap file (with request parsed)

    Returns:
        dict: Formatted entry
    """
    raw_request = entry["request"]["http_request_raw"].replace("\r\n", "\n")

    req = list(filter(None, raw_request.split("\n")))
    (method, uri, version) = req[0].split(" ")

    return {
        "uri": uri,
        "method": method,
        "version": version.replace("HTTP/", ""),
        "headers": req[1:],
        "payload": entry["request"]["payload"],
        "fingerprint": entry["fingerprint"]["fingerprint"]
    }


def format_pcap_cpp(pcap_data):
    """Format whole pcap data for cpp tests

    Args:
        pcap_data (list): Read data from pcap file (with request parsed)

    Returns:
        list: Formatted pcap data
    """
    return [format_entry_cpp(entry) for entry in pcap_data]


# Main

if __name__ == "__main__":
    available_filters = get_methods(SCRIPT_DIR, 'filters', 'convert_filter')

    args = docopt(__doc__.replace(
        '{{ filters }}', f'"{", ".join(list(available_filters.keys()))}"'
    ))

    # Read arguments

    pcap_input = args['<pcap>']
    output = args['--output'] or False

    filters = parse_arg_list(args['--filter'], default=[])
    tags = parse_arg_list(args['--tags'], default=['auto'])

    beautify = args['--beautify'] or False
    mode = 'cpp' if args['--cpp'] else 'dataset'
    force = args['--force'] or False
    verbose = args['--verbose'] or False

    # Check arguments

    if not path.isfile(pcap_input):
        print(f'"{pcap_input}" does not exist')
        sys.exit(1)

    if output and path.isfile(output) and not force:
        print(
            f'Output file "{output}" already exists, use "--force" to overwrite')
        sys.exit(1)

    unavailable_filters = [
        f for f in filters
        if f not in available_filters and f != 'default'
    ]

    if len(unavailable_filters) > 0:
        print(f'Invalid filters: {", ".join(unavailable_filters)}')
        sys.exit(1)

    # Read pcap

    (pcap, fingerprints) = read_pcap(pcap_input)

    data = [
        # Forge entry with full read data from pcap, parsed request with payload
        # and fingerprint from hfinger
        {"pcap": p, "request": get_request(p), "fingerprint": fp, "tags": []}
        for p, fp in zip(pcap, fingerprints)
    ]

    # Apply filters

    data = apply_filters(
        data,
        [(f, available_filters[f]) for f in filters]
    )

    # Add tags

    for tagname in tags:
        data = tag_data(data, tagname)

    # Output data

    if mode == 'cpp':
        data = format_pcap_cpp(data)

    if output:
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4 if beautify else None)

        print(f'Done. Result written to {output} ({len(data)} entries).')
    else:
        print(json.dumps(data, indent=4 if beautify else None))
