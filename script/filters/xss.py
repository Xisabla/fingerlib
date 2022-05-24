from filters.common import tag

keywords = [
    "%3Cscript%3E",
    "<script>",
]

def check_entry(entry):
    """Check for script tag in the entry's payload."""
    payload = entry["request"]["payload"] + entry["request"]["raw"]

    return True in [keyword in payload for keyword in keywords]


def convert_filter(data):
    """Return all entries from pcap that contain a script tag in the payload."""
    return [tag(entry, 'xss') for entry in data if check_entry(entry)]
