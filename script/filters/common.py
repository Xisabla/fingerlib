def tag(entry, tagname):
    """Tag an entry"""
    if not "tags" in entry:
        entry["tags"] = []

    if not tagname in entry["tags"]:
        entry["tags"].append(tagname)

    return entry
