#!/bin/bash

uv run ../bootloader/proxyclient/tools/chainload.py -r build/m1n1.bin
uv run proxyclient/tools/run_guest.py kernelcache.macho amfi_allow_only_tc_override=2
