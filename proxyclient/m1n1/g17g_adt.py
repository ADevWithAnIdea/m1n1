# SPDX-License-Identifier: GPL-2.0-only
"""G17G segment metadata and code exclusions, with no capture/HV dependency.

Only ADT metadata is decoded here. No firmware segment contents are read.
"""

import struct


ASC_NODES = (("primary", "/arm-io/gfx-asc"),
             ("secondary", "/arm-io/gfx1-asc"))


def segment_metadata(adt):
    result = {}
    for instance, path in ASC_NODES:
        properties = adt[path]._properties
        names = properties.get("segment-names", "")
        if isinstance(names, bytes):
            names = names.rstrip(b"\0").decode("ascii")
        if not isinstance(names, str):
            raise RuntimeError("segment-names is not an ASCII string")
        names = [name for name in names.split(";") if name]
        ranges = properties.get("segment-ranges", b"")
        if not isinstance(ranges, (bytes, bytearray)):
            raise RuntimeError("%s segment-ranges is not bytes" % path)
        if len(ranges) != len(names) * 0x20:
            raise RuntimeError(
                "%s segment metadata mismatch: %d names, %#x bytes"
                % (path, len(names), len(ranges)))
        segments = []
        for index, name in enumerate(names):
            field0, field1, field2, size = struct.unpack_from(
                "<QQQI4x", ranges, index * 0x20)
            if not field0 or not size:
                raise RuntimeError("%s segment %s has an empty range" % (path, name))
            segments.append(dict(index=index, name=name, field0=field0,
                                 field1=field1, field2=field2, size=size))
        if not any(segment["name"] == "__TEXT" for segment in segments):
            raise RuntimeError("%s has no named __TEXT segment" % path)
        result[instance] = segments
    return result


def exclusion_ranges(segments):
    result = []
    for instance, entries in segments.items():
        for segment in entries:
            if segment["name"] != "__TEXT":
                continue
            for field in ("field0", "field2"):
                start, size = int(segment[field]), int(segment["size"])
                item = dict(start=start, end=start + size, size=size,
                            name="%s-__TEXT-%s" % (instance, field),
                            source="ADT named __TEXT")
                if not any(old["start"] == item["start"] and old["end"] == item["end"]
                           for old in result):
                    result.append(item)
    return result
