# SPDX-License-Identifier: MIT
"""Open-source Mesa G13 helper executable used by G17P compute probes.

The payload is generated from Mesa's ``src/asahi/libagx/helper.cl`` as
``libagx_helper_0_g13g``.  The generated array begins with a 40-byte
``agx_precompiled_kernel_info`` record; this module retains only its declared
0x302-byte executable body.  It contains no captured Apple code or state.
"""

import base64
import hashlib


MESA_HELPER_G13G_SIZE = 0x302
MESA_HELPER_G13G_SHA256 = (
    "a345ced152adb615ec2309af57917f3fc5c19f889467aa9a3e1184d838e9ec32"
)
_MESA_HELPER_G13G_BASE64 = (
    "ADAKRXIJEghyDRMIcgUUAGIVAAAAAAUhBAUAwBIAYgAAADgAIAAGACggchkQCHId"
    "EghSCEwCAAAgwCABAACeIUKGAQAAAf4lSgqAAI4rEAA1AAAADitEQzUAAAAFMQQF"
    "EMASADgAUihMgiQAIMCuAAAAjjMUADkAAAAOM4SDNQAAAAVhCAUQwBIAjjlMFgAA"
    "AAA4ABI9WMIlWMBFRXEEBRDAMgCOIyAANQAAAA4jhAM1AAAABVHgRhDAEgA4AQ4p"
    "VBYAAAAARVHgRhDAEgAOI0SDAAAAAB4dQrYAAAAABUHgBhDEMgA4AAVBwAYQyPIA"
    "OAB1QAEFAMAQAHVIEQUAwBAAdVAhBQDAEAB1WDEFAMAQACAABgAoMDgBQgoAAAAA"
    "jhsYADUAAAAOG0TDNAAAAAVBDAUAwBIAOAAOIVAWAAAAAEVBDAUAwBIAIAAGACgx"
    "OABSDgAAAABCCgAAAAAgwDoBAABSCEwSAAAgwPYAAACeGUKGAQAAAf4dSgqAAI4b"
    "EMA0AAAADhtEwzQAAAAFQQwFAMASADgAUghQAgAAIAAGACgxQgoAAAAAIMCwAAAA"
    "DiFQHgAAAABFQQwFAMASAHUwAAUAwBAADitEgwAAAAAeHUK2AAAAAAVh5EYQxDIA"
    "OAFFMQgGEcgSAHUwEAUAwBAABWHkRhDEMgA4AQ4zWEMAAAAARTEIRhHIEgB1MCAF"
    "AMAQAAVh5AYQxDIAOAAOM1iDAAAAAEUxCAYRyBIAdTAwBQDAEAAFUeQGEMQyADgA"
    "DitUwwAAAABFMQQGEcgSACAABgAoMDgAOAFSDgAAAABCCgAAAABSCExCAAAgAAYA"
    "KDFCCgAAAAASAExSAEBAEEIAAAAAACAABgAoMVIOAAAAAFIOAAAAAFIOAAAAAADA"
    "hv3//1IOAAAAAFIITPIAAPWW9TP1mvUD9ZlCCgAAAACuBQDAJAgAAOIJAACt3n4R"
    "RCrkAH4FAAiAAEUJCAUAwBIAOAD1lvUz9Zr1A/WZUg4AAAAAiAAIAAgACAAIAAgA"
    "CAA="
)


def mesa_helper_g13g_code():
    """Return the exact open-source helper executable body."""
    code = base64.b64decode(_MESA_HELPER_G13G_BASE64)
    if len(code) != MESA_HELPER_G13G_SIZE:
        raise RuntimeError("Mesa G13 helper fixture has the wrong size")
    if hashlib.sha256(code).hexdigest() != MESA_HELPER_G13G_SHA256:
        raise RuntimeError("Mesa G13 helper fixture hash mismatch")
    return code


def build_mesa_helper_g13g_code_image(size=0x4000):
    """Place the helper at offset zero in a zero-filled executable BO."""
    code = mesa_helper_g13g_code()
    if size < len(code):
        raise ValueError("helper code image is smaller than its executable")
    image = bytearray(size)
    image[:len(code)] = code
    return bytes(image)
