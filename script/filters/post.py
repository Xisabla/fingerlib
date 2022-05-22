from filters.common import tag


def check_entry(entry):
    """Check for POST request in the entry"""
    req = entry["request"]["parsed"][0]

    return req[0:4] == "POST"


def convert_filter(data):
    """Return all entries from pcap that contain a POST request."""
    return [tag(entry, 'post') for entry in data if check_entry(entry)]
