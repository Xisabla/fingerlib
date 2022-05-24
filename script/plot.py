#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import pandas as pd
import matplotlib.pyplot as plt

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

# Generic data transformations

def transform_bars(entries):
    values = list(set(entries))
    values.sort()

    dt = [ entries.count(v) for v in values ]
    
    return (dt, values)

# Plot methods

def plot_uri_length(entries, ax=None, bars=False):
    # Bars
    if bars:
        dt, values = transform_bars(entries)
        df = pd.DataFrame({ 'labels': values, 'URI length': dt })

        return df.plot.barh(x='labels', y='URI length',
            xlabel='', ylabel='count',
            title=f'URI length (total: {len(entries)})', ax=ax)
    
    # Density
    df = pd.DataFrame(entries)
    return df.plot.kde(title=f'URI length (total: {len(entries)})', ax=ax)

def plot_uri_dir_count(entries, ax=None, bars=False):
    # Bars
    if bars:
        dt, values = transform_bars(entries)
        df = pd.DataFrame({ 'labels': values, 'URI directory count': dt })


        return df.plot.barh(x='labels', y='URI directory count',
            xlabel='', ylabel='count',
            title=f'URI directory count (total: {len(entries)})', ax=ax)

    # Density
    df = pd.DataFrame(entries)
    return df.plot.kde(title=f'URI directory count (total: {len(entries)})', ax=ax)

def plot_uri_dir_avg_size(entries, ax=None, bars=False):
    # Bars
    if bars:
        dt, values = transform_bars(entries)
        df = pd.DataFrame({ 'labels': values, 'Directory average size': dt })


        return df.plot.barh(x='labels', y='Directory average size',
            xlabel='', ylabel='count',
            title=f'Directory average size (total: {len(entries)})', ax=ax)

    # Density
    df = pd.DataFrame(entries)
    df.plot.kde(title=f'Directory average size (total: {len(entries)})', ax=ax)

def plot_uri_ext(entries, ax=None):
    dt, values = transform_bars(entries)
    df = pd.DataFrame({
        'labels': list(map(lambda x: 'None' if x == '' else x, values)),
        'Extensions': dt
    })

    return df.plot.bar(x='labels', y='Extensions',
        xlabel='', ylabel='count',
        title=f'Extensions (total: {len(entries)})', ax=ax)

def plot_query_size(entries, ax=None):
    df = pd.DataFrame(entries)
    df.plot(kind='kde', title=f'Query size (total: {len(entries)})', ax=ax)

def plot_query_avg_size(entries, ax=None):
    df = pd.DataFrame(entries)
    return df.plot(kind='kde', title=f'Query average size (total: {len(entries)})', ax=ax)

def plot_http_method(entries, ax=None):
    dt, values = transform_bars(entries)

    df = pd.DataFrame({ 'method': values, 'HTTP method': dt })
    return df.plot.bar(x='method', y='HTTP method',
        title=f'HTTP method (total: {len(entries)})', ax=ax)

def plot_http_version(entries, ax=None):
    dt, values = transform_bars(entries)

    df = pd.DataFrame({ 'version': values, 'HTTP version': dt })
    return df.plot.bar(x='version', y='HTTP version',
        title=f'HTTP version (total: {len(entries)})', ax=ax)

def plot_headers(entries, ax=None):
    # Note: heavy method as each request might have a different values
    read_headers = {}

    for headers in entries:
        for header in headers.split('/'):
            header = header.replace(':', '_')
            if not header in headers:
                read_headers[header] = 0
            
            read_headers[header] += 1
    
    df = pd.DataFrame(read_headers, index=['count'])
    return df.plot.bar(title=f'Headers (total: {len(entries)})', ax=ax)

def plot_all_headers(entries, ax=None):
    headers = [
        header for headers in [ h.split(',') for h in entries ]
        for header in headers
    ]
    dt, values = transform_bars(headers)

    df = pd.DataFrame({ 'headers': values, 'Headers': dt })
    return df.plot.barh(x='headers', y='Headers',
        title=f'Headers', ax=ax)

def plot_payload_flag(entries, ax=None):
    dt, values = transform_bars(entries)
    df = pd.DataFrame({
        'labels': list(map(lambda x: 'None' if x == '' else x, values)),
        'Payload flag': dt
    })

    return df.plot.bar(x='labels', y='Payload flag',
        xlabel='', ylabel='count',
        title=f'Payload flags (total: {len(entries)})', ax=ax)

def plot_payload_length(entries, ax=None):
    df = pd.DataFrame(entries)
    return df.plot.kde(title='Payload length', ax=ax)

def plot_payload_entropy(entries, ax=None, bars=False):
    # Bars
    if bars:
        dt, values = transform_bars(entries)
        df = pd.DataFrame({ 'labels': values, 'Payload entropy': dt })

        return df.plot.bar(x='labels', y='Payload entropy',
            xlabel='', ylabel='count',
            title=f'Payload entropy (total: {len(entries)})', ax=ax)

    # Density
    df = pd.Series(entries)
    return df.plot.kde(title=f'Payload entropy (total: {len(entries)})', ax=ax)

if __name__ == "__main__":
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        print(f'Usage: {__file__} <input_file>')
        sys.exit(1)

    values = read_data(sys.argv[1])

    # Plot

    # plot_uri_length(values['uri_length']) # irrelevant
    # plot_uri_dir_count(values['uri_dir_count']) # irrelevant
    # plot_uri_dir_avg_size(values['uri_dir_avg_size']) # irrelevant
    # plot_uri_ext(values['uri_ext']) # irrelevant
    # plot_query_size(values['uri_query_size']) # irrelevant
    # splot_query_avg_size(values['uri_query_avg_size']) # irrelevant
    # plot_http_method(values['http_method'])
    # plot_http_version(values['http_version']) # irrelevant>
    # plot_headers(values['headers']) # irrelevant, too many headers (in general)
    # plot_all_headers(values['all_headers'])
    # plot_payload_flag(values['payload_flag'])
    # plot_payload_length(values['payload_length'])
    # plot_payload_entropy(values['payload_entropy'])

    plt.show()
