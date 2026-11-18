"""Reads uploaded files. Deliberately vulnerable: the name is concatenated
into the path, so "../" escapes the uploads directory (CWE-22)."""


def read_upload(filename):
    with open("uploads/" + filename) as handle:
        return handle.read()
