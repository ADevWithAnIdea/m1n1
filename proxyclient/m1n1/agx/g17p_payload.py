# SPDX-License-Identifier: MIT
"""Helpers for narrowing source-workload page dependencies on G17P."""


PAGE_SIZE = 0x4000


def parse_page_selector(value, allowed_pages, page_size=PAGE_SIZE):
    """Parse comma-separated pages or half-open page ranges.

    Selectors use Python-style integer syntax.  A range such as
    ``0x10000:0x18000`` includes every page beginning at the left endpoint and
    excludes the right endpoint.  Every selected page must belong to the
    caller-provided inventory so a typo cannot blank unrelated live state.
    """
    allowed = {int(page) for page in allowed_pages}
    if not value or not value.strip():
        return set()

    selected = set()
    for raw_token in value.split(","):
        token = raw_token.strip()
        if not token:
            raise ValueError("empty G17P page selector")
        if ":" in token:
            fields = token.split(":")
            if len(fields) != 2 or not all(fields):
                raise ValueError("invalid G17P page range %r" % token)
            start, end = (int(field, 0) for field in fields)
            if start >= end:
                raise ValueError("empty G17P page range %r" % token)
            pages = range(start, end, page_size)
        else:
            pages = (int(token, 0),)
        for page in pages:
            if page & (page_size - 1):
                raise ValueError("unaligned G17P page %#x" % page)
            if page not in allowed:
                raise ValueError(
                    "G17P page %#x is outside the payload inventory" % page)
            selected.add(page)
    return selected
