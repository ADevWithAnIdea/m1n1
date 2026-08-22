# SPDX-License-Identifier: MIT
"""Generation-safe entrypoint for the embedded T8140 DRM shim.

``m1n1.hw.uat`` fixes its top-level address split when the module is imported.
The generic ``m1n1.agx`` package therefore must not be imported until the ADT
has selected G17; importing ``m1n1.agx.shim`` directly starts from the default
G13 split and builds truncated translation roots.
"""

from .setup import u
from .constructutils import Ver

Ver.set_version(u)
if Ver._version.get("V") is None:
    Ver.set_version_key("V", Ver.MATRIX["V"][-1])

from .agx.shim import DRMAsahiShim  # noqa: E402

Shim = DRMAsahiShim

__all__ = ["DRMAsahiShim", "Shim"]
