from filters.common import tag

keywords = [
    "SELECT",
    "UPDATE",
    "DELETE",
    "INSERT",
    " AND ",
    " OR ",
    " ORDER BY "
]


def check_entry(entry):
    """Check for SQL keywords in the entry's payload."""
    http = entry['request']['raw']
    payload = entry["request"]["payload"]
    return True in [keyword in http for keyword in keywords] \
        or (len(payload) > 0 and [keyword in payload for keyword in keywords])


def convert_filter(data):
    """Return all entries from pcap that contain a SQL request in the payload."""
    return [tag(entry, 'sql') for entry in data if check_entry(entry)]
