# Neo GPU experiment provenance archive

This snapshot records independently developed T8140/G17P GPU work behind the
[Neo Rust kernel driver](https://github.com/GravityLinux/linux/tree/PUBLIC_neo_agx_rust_driver).
It contains original Metal/OpenCL/graphics workloads, GPU descriptor and
command-stream builders, observation/comparison scripts, and historical tests.
These files document the investigation; they are not a complete runnable shim
or a supported tool package. Imports may refer to deliberately omitted modules.

The archive excludes all UAT/address-translation code and related experiments,
including files that mix them with GPU work. Emulator code, emulator-private
state/root layouts, host handoff seeds, bootloader/hypervisor core changes,
local operator instructions, compiled workload images, and binary capture
artifacts are also omitted. The public branch has a single snapshot commit
on the existing clean public base; private development history is not included.

The retained source content is preserved; one extra blank line at EOF was removed. The
[manifest](neo-gpu-experiments-manifest.json) lists their SHA-256 hashes and the
audit scope. Python, shell, and plist syntax was checked. No runtime validation
is claimed for this deliberately incomplete archive.

Some tests retain small command or status DATA examples to compare against
field-by-field builders. They contain no Apple driver or firmware executables.
Arguments called `firmware_state` in render/compute builders name ordinary
per-submission support pages and firmware-owned queue fields, not an emulator
translation-state object. The original workload sources are retained rather
than their precompiled executable images.
