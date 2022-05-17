from hfinger.analysis import hfinger_analyze
import sys
from json import dump
import pyshark

if __name__ == "__main__":
    
    # check args
    if len(sys.argv) != 2:
        print("Usage:python pcap_script.py <pcap file path>")
        quit()
    
    result = []
    path = sys.argv[1]

    # get fingerprints
    fingerprints = hfinger_analyze(path)

    # open pcap file
    filtered_cap = pyshark.FileCapture(path, display_filter='http.request.method')

    # associate fingerprint with packet http info
    for request, fp in zip(filtered_cap, fingerprints):
        result.append((request.http._all_fields, fp))
    
    # write result to json file
    with open('result.json', 'w') as file:
        dump(result, file)
        
    #one liner
    #with open('r.json','w')as file:json.dump([(r.http._all_fields, f)for r,f in zip(pyshark.FileCapture(path,display_filter='http.request.method'),hfinger_analyze(path))],file)
    