# SPDX-License-Identifier: GPL-2.0-only
"""Native-derived sparse predecessor descriptor for mixed partial render."""
import base64
import hashlib
import zlib
import struct

PAGE_SIZE = 0x4000
_PAGE_B85 = (
    "c-rmMF=!J}7zgn0e>rU^L4({-H0n``1PKyokfN1z=pY!dLkGbQ9XdF4DA>WFm=hcv92^`R92^`Zb#QQSaLC}`ptv}Q2o`a0aJa!CLhR@N0^P(5T*c-8Bmb8n_ujj_@8g;MUkiB;MA?vB-tP5!Z{Kt-%+6kK-%676W6v+TzuD^5i9+)W?eD(p+r0w&*KCR7C4{9(iw;EDS$fx<E0=6&!+y^6($FegBeEH5*`h7mnr&KY4V$-)t=PJ487$y~Au|Y3Mg>(wm_iLPW>7~1O|&qFc`RTN7tz5ImT?6uSj8HyVI3RT#0_jA!EM~ZUEITcJitRd!eitfAo9+S>1HkD&X4n7hofWT7;tXL9AqY$3Ui35GDnz*nPQGIHRc2pGt<l|rp}yZ8q67{$+VcW%p7wLW3|9v`zudg{q`!7RbzV0dStb@`NwKJ!BafLbG*Py^zjO>@g5)W5udPwulR=VNbv&$4A~Q5P!1|V(f4<6A9nAug8h`=ZeiBFnUlw}s*d{DcD@*V!X0}J5wa)C?A)rwHi(<S=uuAMT5bRQ?w5O-t&y$o$M|E+)R_$?HQV)lyg!nEdH*EEui#?+_tQi~L_|bHL_|bHL_|bHL_|bHL_|bHL_|bHL_}mC{RV5#k}?"
)

def page():
    body = zlib.decompress(base64.b85decode(_PAGE_B85))
    if len(body) != PAGE_SIZE:
        raise ValueError("invalid native mixed descriptor page")
    # The embedded variant is the replay-minimal form; callers may restore
    # native predecessor fields when testing full-page admission.
    return body

def full_page():
    body = bytearray(page())
    struct.pack_into("<Q", body, 0x00, 0x40)
    struct.pack_into("<Q", body, 0x40, 0x40)
    struct.pack_into("<Q", body, 0x60, 0x75B60000000)
    return bytes(body)
