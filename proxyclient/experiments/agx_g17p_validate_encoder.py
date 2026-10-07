#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require the modelled tiler encoder to rebuild a captured one byte for byte.

The encoder is the only object hardware has shown to decide whether anything is drawn, so a builder
for it has to be checked before a boot is spent on it. This parses a captured stream into
parameters, rebuilds it from those parameters, and requires the result to be identical.

Round-tripping is a weaker test than an independent derivation, and it is the honest one here: most
of the header is still carried as named constants rather than derived, and a gate that pretended
otherwise would be the kind of over-scoped check this project keeps having to withdraw.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.agx import g17p_encoder


# The first submission's stream, read from the render context of a captured boot.
CAPTURED = bytes.fromhex(
    "2e004000" "00000000" "00000001" "00600600"
    "06060000" "00000000" "00000000" "00050000"
    "c0020000" "00070000" "00800500" "00050000"
    "1c800500" "00070000" "30800500" "00050000"
    "4c800500" "000a0000" "00890600" "00030000"
    "60800500" "00020000" "6c800500" "00020000"
    "00800400" "01000040" "ffff0000" "0006f261"
    "0002bc01" "06000000" "01000000" "00000000"
    "7fff0000" "01000000" "000000c0"
)
CONTEXT_BASE = 0x1000000000


def main():
    failures = 0

    def check(label, condition, detail=""):
        nonlocal failures
        print("  %-46s %s" % (label, "OK" if condition else "FAIL"))
        if not condition:
            failures += 1
            if detail:
                print("      %s" % detail)

    check("captured stream is the modelled size",
          len(CAPTURED) == g17p_encoder.ENCODER_SIZE,
          "%d bytes, model says %d" % (len(CAPTURED), g17p_encoder.ENCODER_SIZE))

    params = g17p_encoder.parse_encoder(CAPTURED, CONTEXT_BASE)
    rebuilt = g17p_encoder.build_encoder(params)

    differing = [index for index in range(min(len(rebuilt), len(CAPTURED)))
                 if rebuilt[index] != CAPTURED[index]]
    check("rebuild is byte-exact", not differing,
          "differs at %s" % ["%#x" % index for index in differing[:12]])

    check("eight bind pairs", len(params.binds) == g17p_encoder.BIND_PAIR_COUNT)
    check("bind addresses are render-context resident",
          all(bind.address == 0 or bind.address >= CONTEXT_BASE for bind in params.binds))

    # The two fields hardware separated, which the builder must place exactly.
    check("gating opcode is at +0x6e",
          params.opcode == g17p_encoder.DRAW_OPCODE_INDEXED_16,
          "%#x" % params.opcode)
    check("primitive selector is at +0x6d",
          params.primitive == g17p_encoder.PRIMITIVE_TRIANGLE,
          "%#x" % params.primitive)
    check("opcode lands in the word hardware gated",
          rebuilt[0x6e:0x70] == CAPTURED[0x6e:0x70])
    check("primitive lands in the byte hardware did not gate",
          rebuilt[0x6d] == CAPTURED[0x6d])

    check("draw config word", params.draw_config == 0x40000001, "%#x" % params.draw_config)
    check("restart comparand", params.restart_comparand == 0xffff,
          "%#x" % params.restart_comparand)
    check("index count is six", params.index_count == 6, "%d" % params.index_count)
    check("one instance", params.instance_count == 1, "%d" % params.instance_count)
    check("base vertex is zero", params.base_vertex == 0, "%d" % params.base_vertex)

    # Changing a parameter must change exactly the bytes it owns and nothing else.
    params.index_count = 3
    changed = g17p_encoder.build_encoder(params)
    moved = [index for index in range(len(changed)) if changed[index] != rebuilt[index]]
    check("index count owns only its own word",
          moved and all(0x74 <= index < 0x78 for index in moved),
          "changed %s" % ["%#x" % index for index in moved[:12]])

    params.index_count = 6
    params.primitive = 0x09
    changed = g17p_encoder.build_encoder(params)
    moved = [index for index in range(len(changed)) if changed[index] != rebuilt[index]]
    check("primitive owns only its own byte", moved == [0x6d],
          "changed %s" % ["%#x" % index for index in moved[:12]])

    params.primitive = g17p_encoder.PRIMITIVE_TRIANGLE
    params.indirect_args = 0x15_0001_c000
    changed = g17p_encoder.build_encoder(params)
    check("indirect draw selects the indexed-indirect opcode",
          changed[0x6e:0x70] == bytes.fromhex("3264"))
    check("indirect args pointer is high32 then low32",
          changed[0x74:0x7c] == bytes.fromhex("1500000000c00100"),
          changed[0x74:0x7c].hex())
    check("indexed direct tail shifts left by one word",
          changed[0x7c:0x88] == rebuilt[0x80:0x8c],
          "%s != %s" % (changed[0x7c:0x88].hex(), rebuilt[0x80:0x8c].hex()))
    check("indexed indirect leaves no stale word after its terminator",
          changed[0x88:0x8c] == bytes(4), changed[0x88:0x8c].hex())
    reparsed = g17p_encoder.parse_encoder(changed, CONTEXT_BASE)
    check("indexed indirect stream round-trips",
          g17p_encoder.build_encoder(reparsed) == changed)
    check("indexed indirect public argument layout",
          g17p_encoder.build_indexed_indirect_arguments(6, 1, 0, 0, 0)
          == bytes.fromhex("0600000001000000000000000000000000000000"))

    print()
    if failures:
        print("%d checks failed" % failures)
        return 1
    print("G17P tiler encoder gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
