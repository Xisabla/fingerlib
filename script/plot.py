#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import pandas as pd
import matplotlib.pyplot as plt

# plots

# Ordered fields of fingerprint
FIELDS = [
    'uri_length',
    'uri_dir_count',
    'uri_dir_avg_size',
    'uri_ext',
    'uri_query_size',
    'uri_query_count',
    'uri_query_avg_size',
    'http_method',
    'http_version',
    'all_headers',
    'headers',
    'payload_flag',
    'payload_entropy',
    'payload_length'
]

# Fields that need a numeric conversion
NUMERIC_FIELDS = [
    'uri_length',
    'uri_dir_count',
    'uri_dir_avg_size',
    'uri_query_size',
    'uri_query_count',
    'uri_query_avg_size',
    'payload_length',
    'payload_entropy'
]

def read_data(file):
    """Read values from dataset

    Args:
        file (string): Path to dataset

    Returns:
        dict: Parsed values of each field from the dataset
    """
    with open(file, 'r', encoding='utf-8') as f:
        data = json.load(f)

        values = {
            k: [] for k in FIELDS
        }

        for entry in data:
            fp = entry['fingerprint']['fingerprint']
            fi = 0

            for v in fp.split('|'):  
                field = FIELDS[fi]

                if field in NUMERIC_FIELDS:
                    v = 0 if v == '' else float(v)
                
                values[field].append(v)
                fi += 1
    
        return values

# Plot methods

def plot_headers(entries, ax=None):
    read_headers = {}

    for headers in entries:
        for header in headers.split('/'):
            header = header.replace(':', '_')
            if not header in headers:
                read_headers[header] = 0
            
            read_headers[header] += 1
    
    df = pd.DataFrame(read_headers, index=['count'])
    df.plot(kind='bar', title='Headers', ax=ax)

def plot_all_headers(entries, ax=None):
    all_headers = {}

    for headers in entries:
        for header in headers.split(','):
            if not header in all_headers:
                all_headers[header] = 0
            
            all_headers[header] += 1
    
    df = pd.DataFrame(all_headers, index=['count'])
    df.plot(kind='bar', title='Headers', ax=ax)

def plot_payload_length(entries, ax=None):
    df = pd.DataFrame(entries)
    df.plot(kind='kde', title='Payload length', ax=ax)

def plot_payload_entropy(entries, ax=None):
    df = pd.DataFrame(entries)
    df.plot(kind='kde', title='Payload entropy', ax=ax)

if __name__ == "__main__":
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        print(f'Usage: {__file__} <input_file>')
        sys.exit(1)

    values = read_data(sys.argv[1])

    # Plot

    fig, ax = plt.subplots(2, 2)
    
    # plot_headers(values['headers'])
    plot_all_headers(values['all_headers'])
    plot_payload_length(values['payload_length'], ax[1,0])
    plot_payload_entropy(values['payload_entropy'], ax[1, 1])

    plt.show()
