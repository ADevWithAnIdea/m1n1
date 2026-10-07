# SPDX-License-Identifier: MIT
"""Source descriptor reduction over explicit inputs decoded from a native model.

This is not an allocator or a cold source workload. The capture adapter is kept
separate from the reusable byte constructors in m1n1/agx.
"""
import importlib.util
import struct
import sys
import types
from pathlib import Path


def constructors():
    package_name = "g17p_descriptor_reduction"
    if package_name not in sys.modules:
        directory = Path(__file__).resolve().parents[1] / "m1n1/agx"
        package = types.ModuleType(package_name)
        package.__path__ = [str(directory)]
        sys.modules[package_name] = package
        for name in ("g17p", "g17p_submission", "g17p_render", "g17p_backend"):
            qualified = package_name + "." + name
            spec = importlib.util.spec_from_file_location(qualified, directory / (name + ".py"))
            module = importlib.util.module_from_spec(spec)
            sys.modules[qualified] = module
            spec.loader.exec_module(module)
    return tuple(sys.modules[package_name + "." + name]
                 for name in ("g17p_submission", "g17p_render", "g17p_backend"))


def build_pair(read, tiling_descriptor, fragment_descriptor):
    submission, render, backend = constructors()
    descriptors = dict(tiling=tiling_descriptor, fragment=fragment_descriptor)
    captured = {kind: read(address, backend.G17PWorkBuilder.BODY_STRIDE[kind])
                for kind, address in descriptors.items()}
    registers = {}
    for kind, offset, header in (("tiling", 0x60, 0x768), ("fragment", 0xa0, 0x7a8)):
        count = struct.unpack_from("<I", captured[kind], header)[0] & 0xffff
        if count != (73 if kind == "tiling" else 89):
            raise ValueError("unqualified descriptor register count")
        registers[kind] = [struct.unpack_from("<IQ", captured[kind], offset + i * 12)
                           for i in range(count)]
    value = lambda kind, number: next(v for n, v in registers[kind] if n == number)
    ta = lambda number: value("tiling", number)
    frag = lambda number: value("fragment", number)
    fq = lambda offset: struct.unpack_from("<Q", captured["fragment"], offset)[0]
    tq = lambda offset: struct.unpack_from("<Q", captured["tiling"], offset)[0]
    dims = frag(0x15211)
    context_base = frag(0x16429) - ta(0x1c039)
    params = render.G17PRenderParameters(
        width=dims & 0xffffffff, height=dims >> 32, context_base=context_base,
        tilemap=frag(0x16429), heapmeta=frag(0x16060), tpc=context_base + ta(0x1c0a1),
        deflake_1=context_base + ta(0x10111), deflake_2=context_base + ta(0x10119),
        deflake_3=context_base + (ta(0x1c950) & ~0x4000000000000),
        encoder=context_base + ta(0x1c880), ta_status=ta(0x14318) & ~1,
        fragment_status=frag(0x14080) & ~1,
        store_pipeline_bind=frag(0x15379), store_pipeline=frag(0x15381),
        load_pipeline_bind=frag(0x15369), load_pipeline=frag(0x15371),
        partial_load_pipeline_bind=fq(0x1ea8), partial_load_pipeline=fq(0x1eb0),
        partial_store_pipeline_bind=struct.unpack_from("<I", captured["fragment"], 0x1f98)[0],
        partial_store_pipeline=fq(0x1f9c),
        scissor_array=frag(0x15109), depth_bias_array=frag(0x15101), aux_fb=frag(0x16461),
        tib_blocks=frag(0x10051), tile_config=frag(0x10039),
        aux_fb_flags=frag(0x15021), aux_fb_page_count=frag(0x15049),
        utile_config=frag(0x10009), multisample_control=frag(0x10019), ppp_control=ta(0x10121),
        depth_clear_value_bits=frag(0x15301), process_empty_tiles=bool(captured["fragment"][0x2124]),
        timestamp_a=tq(0x8fe), ta_timestamp_end=tq(0x906),
        ta_user_timestamp_start=tq(0x90e), ta_user_timestamp_end=tq(0x916),
        fragment_timestamp_start=fq(0x2198), fragment_timestamp_end=fq(0x21a0),
        fragment_user_timestamp_start=fq(0x21a8), fragment_user_timestamp_end=fq(0x21b0),
        queue_pair=struct.unpack_from("<I", captured["tiling"], 0x8ba)[0] // 2)
    generated_registers = dict(tiling=render.build_tiling_registers(params),
                               fragment=render.build_fragment_registers(params))
    # These are explicit scheduler inputs, not caller rendering resources.
    # Their ownership/lifetime is a later runtime reduction. The source recipe
    # determines every register number, order and other value.
    scheduler_registers = {
        "tiling": {0x1ca30, 0x16c39, 0x1c910, 0x1ca10, 0x14a1, 0xa349,
                   0x10209, 0x1c9f0, 0x14320, 0xa5a1},
        "fragment": {0x160e0, 0x1499, 0xa341, 0x1ca28, 0x10211, 0x10420, 0xa5a9},
    }
    for kind in registers:
        generated_registers[kind] = [(number, value(kind, number)
                                     if number in scheduler_registers[kind] else
                                     params.queue_pair if number in (0x1c830, 0x1c838) else scalar)
                                    for number, scalar in generated_registers[kind]]
        if generated_registers[kind] != registers[kind]:
            differences = [(i, a, b) for i, (a, b) in enumerate(
                zip(generated_registers[kind], registers[kind])) if a != b]
            raise ValueError("source register recipe differs: %s %r" % (kind, differences))
    result = {}
    for kind, address in descriptors.items():
        body = captured[kind]
        qword = lambda offset: struct.unpack_from("<Q", body, offset)[0]
        word = lambda offset: struct.unpack_from("<I", body, offset)[0]
        grid = word(0x8ba if kind == "tiling" else 0x2154)
        index = word(0x7a8 if kind == "tiling" else 0x90) - 1
        writes = []
        builder = backend.G17PWorkBuilder(lambda size, label: address,
                                          lambda dva, data: writes.append(bytes(data)), kind=kind)
        builder.write_item_fields = builder.write_structural_tail = builder.write_lifecycle_fields = True
        offsets = (0x10, 0x20, 0x28, 0x30) if kind == "tiling" else (0x20, 0x28, 0x30, 0x38)
        objects = [qword(offset) for offset in offsets]
        builder.array_a, builder.array_b = objects[0], objects[2]
        builder.tail_pointer_overrides = {offset: qword(offset)
                                         for offset, _, _ in builder.TAIL_POINTERS[kind]}
        builder.item(index, (objects[1], objects[3]), generated_registers[kind], 0, 0,
                     context_id=word(0xc), record_indices=(0, 0),
                     submission_ordinal=2, queue_pair=grid // 2,
                     parameters=params, submit_sequence=qword(4), queue_grid_index=grid)
        generated = bytearray(writes[0])
        # The minimal native chain has explicit nodes 0,1,2. Do not use the
        # old unrelated capture's inferred 0,1,3 sequence for this workload.
        node = struct.unpack_from("<I", captured["tiling"], 0x48)[0]
        ordinal = submission.DESCRIPTOR_ORDINAL_FIELDS[kind]
        for offset in ordinal["work"]:
            struct.pack_into("<I", generated, offset, node)
        for offset in ordinal["stamps"]:
            struct.pack_into("<I", generated, offset, (max(1, word(0xc)) << 8) + node)
        # Qualified minimal partial-layout variant. These scalar fields are
        # equal in A1/B1/A2; their broader meanings remain uncharacterized.
        if kind == "tiling":
            generated[0x789] = 8
            struct.pack_into("<H", generated, 0x93e, 0x91d0)
        else:
            struct.pack_into("<I", generated, 0x215c, 0)
            struct.pack_into("<H", generated, 0x21d8, 0xa210)
            generated[0x222d] = 0
        generated = bytes(generated)
        differences = [i for i, (a, b) in enumerate(zip(generated, body)) if a != b]
        result[kind] = dict(address=address, body=generated, captured=body,
                             differences=differences, inputs=dict(
                                 grid=grid, item_index=index, node=node, context_id=word(0xc),
                                 submit_sequence=qword(4), objects=objects,
                                 tail_pointers=builder.tail_pointer_overrides,
                                 scheduler_registers=[(n, v) for n, v in registers[kind]
                                                      if n in scheduler_registers[kind]]))
    return result, params


def snapshot_pair(manifest, ram):
    ordinal = int(manifest["native_sequence_ordinal"])
    if not 1 <= ordinal <= 3:
        raise ValueError("descriptor reduction requires the qualified A/B/A chain")
    mappings = {int(row["va"]): row for row in manifest["mappings"]}

    def read(address, size):
        body = bytearray()
        while size:
            offset = address & 0x3fff
            row = mappings[address - offset]
            count = min(size, 0x4000 - offset)
            start = int(row["blob_index"]) * 0x4000 + offset
            body.extend(ram[start:start + count])
            address, size = address + count, size - count
        return bytes(body)

    qword = lambda address: struct.unpack("<Q", read(address, 8))[0]
    region_b = qword(int(manifest["init_addr"]) + 0x18)
    descriptors = []
    for channel in (6, 7):
        ring = qword(region_b + 0x20 + channel * 0x20 + 24)
        outer = ring + (ordinal - 1) * 0x18
        queue = qword(outer + 8)
        head = struct.unpack("<I", read(outer + 0x14, 4))[0] & 0xffff
        if head not in (3, 6):
            raise ValueError("descriptor reduction has unqualified inner head")
        descriptors.append(qword(qword(queue + 8) + (head - 3) * 8))
    return build_pair(read, *descriptors)


def rebuild_descriptors(manifest, ram):
    import hashlib
    result, params = snapshot_pair(manifest, ram)
    for kind, row in result.items():
        if row["differences"] or len(row["body"]) != len(row["captured"]):
            raise ValueError("source %s descriptor differs at %r" % (kind, row["differences"]))
    report = dict(parameters=params.__dict__, native_model_inputs=True, descriptors=[
        dict(kind=kind, address=row["address"], size=len(row["body"]),
             sha256=hashlib.sha256(row["body"]).hexdigest(), inputs=row["inputs"])
        for kind, row in result.items()])
    return [(row["address"], row["body"]) for row in result.values()], report


def inspect_snapshot(path):
    import json
    manifest = json.loads((path / "manifest.json").read_text())
    ram = (path / manifest["ram_file"]).read_bytes()
    result, params = snapshot_pair(manifest, ram)
    print(params)
    for kind, row in result.items():
        print(kind, hex(row["address"]), len(row["differences"]), "differing bytes")
        for offset in sorted({value & ~3 for value in row["differences"]}):
            a, b = (struct.unpack_from("<I", row[key], offset)[0] for key in ("body", "captured"))
            print("  %#06x: built %#010x native %#010x" % (offset, a, b))


if __name__ == "__main__":
    inspect_snapshot(Path(sys.argv[1]))
