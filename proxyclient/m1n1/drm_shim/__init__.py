# SPDX-License-Identifier: GPL-2.0-only
"""M5 DRM shim and firmware transport, independent of the legacy AGX package."""

from ..constructutils import Ver

# The base UAT module uses these public generation names in its import-time
# version checks. Register them before importing UAT through the shim.
for generation in ("G15", "G15X"):
    if generation not in Ver.MATRIX["G"]:
        Ver.MATRIX["G"].append(generation)
