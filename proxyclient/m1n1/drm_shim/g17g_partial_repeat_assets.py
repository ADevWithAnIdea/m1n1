# SPDX-License-Identifier: GPL-2.0-only
"""Hash-gated caller products for G17G partial generation two.

Generated from the earliest native second-work partial witness.  The
bounded payloads are Metal compiler/resource products in context 1,
not firmware, kernel, scheduler state, or a replay checkpoint.
"""

import base64
import hashlib
import zlib

from . import g17g_partial_assets

PAGE_SIZE = 0x4000
SOURCE_MANIFEST_SHA256 = '5a3bb68bbd19cf6bc1ca034e30b9cb1780f26f35a22618d866b33ea7b9bebb87'
PARTIAL_REPEAT_CONTEXT_RANGES = {
    0x10000000000: (0x3000, 0x3800, 'febddce5bffad42b568c93e07f3cf49ace03fc3c90d4c4beba9e05701e970671', '71aa34f95e3adff7db64f14d6c4046bd73b3b106c031e2c2179fe57b8028b083', '9eaf92eb8dcd171268d36d63623a9a9924b3fd74b7451080cf3b5c5a35977c69'),
    0x100001c8000: (0x100, 0x600, '4c2a843987184e92d201a3762843bdd5769200dd59756e76f458a1063e170c91', '693bb253324c1e1437e2cca66cce6ce36f6a01d4b58c94ce5d53c4566372558d', '6a95f99a73e4b0f34b61da52626448e9cb1b5eab0f912b9538a96929ff8eba85'),
    0x100001e8000: (0x0, 0x800, '06dcd9b8a4bb71ced4d4236f9a5e547029571b58d3d3a7787b0aa72b094efc57', '0f17c296e342ac392413067cd3b276a78c189c8acd5cc904e96929b74e5bc63d', 'e4540d3c5c39a2884537a11f598377a48580ef59c5d7970ed88d6d825da5c64b'),
}

_PARTIAL_REPEAT_FRAGMENTS_B85 = {
    0x10000000000: (
        b'c-o~@&u<$=6n-'
        b'<_>~7Y^9ky|^cG7g$u{VjWCT?xjZUU(jD8+3BiXbACmISpz{HO$nUJ6L;j?)Hms+0?r0NJ&xG>K4vR3cGPW0fBwJ'
        b'#)#G3lb;(1m5o2$wuk{HS5DS?|t9Aw{P|vXF-~eSALFtc%H~_y-wtF7l}M_g~;ivMDDsq<ltvS&XYE3kndsu?`Qy'
        b'h&4{{DlT&3srz(C<VSY|g{T$W&9F4hA82<m$ps=s!1(0Z5uTZC__!PhH3KK(BX68kpDQlJXL!aDQMXR}h1?|-'
        b'wv7pp$mJP;XAc&}PXt&L0Y<ZkUZS#OFjMGvC^WDgIBK9EKW|Sij!b#ig;)1jKTvTBUzyR$dQ5Ci<c?`6Yf%<;b_a'
        b'de^lx#EU?vvlN%|3UZTsn$e4mCrFCpf%so5x&D=(=rYT}`NT61gI3Mi9q2d}*7{yBc=eHcz=4RyvK`dDNUie1*f3'
        b'ZI;T8rbCAf+dSv0I!Y7BPNC{G#0wm@Y;)4Bq;1>g8?HthxP;sl4$<io0pnc`RZCKIsTR|;FF=sN`T@Ln9b<~|w5Z'
        b'Ax3@(HAs;GvxnOp|#l&G>Xo!td(NK`wvbnQ3Lj)<x@kzs#>c0fGTz5Tr=K_TC^$Gz=)-'
        b'23bv_ZoZLJN5+k&Ntm_``tVA)b2(9lKuI&`)ej9?sbTvZ<v{|NwJ?)l)Na!2B1pcBRUY;Cwo!97lEEKU_}8qo6#W'
        b'14WY|21k9c_$V$x1_Hw)vc3sU{9wvndB%l(98JJAU5y%ytwJ^B|`UeJW)v7tWc%80U9wIw$1X?v+wp>?T77;rx8^'
        b'TJ;*KxKUcRL~?``Bn(8TPR^>c?Fc5i9>=h^@VD<(u`mTNx2q#h7dDtx<`ZbM@nE;9-(Qpl(&-'
        b'#F<5p!2O1^7ABL$!z4kQGs0n#8?W4PW=z5*Qs<ujDCX}!^7O5*+?d|q_d6m4pb)yXGzJz%X`Cg6|3=vW8aGp?vsM'
        b'6fk}fCgyamH4sHz1HIe;ukR^j8C(%2l4o(n2cuO;Gq06jp%56?X4@oHa0Z(O^_#H;9y7nhhR{K8&BZ+v24oeFPy;'
        b'{rx8z3fDJ1~K#oez9VvAHJP|@EjM0+kw-UAqX`P`EceAowXMMaJ5VY;8LHJtVk43mlrZM+L-%^=&?blP-'
        b'|Al_gq<s-%uiH|J!}~pm}sZE+hjcGP;f5h)-'
        b'pz3gxj#aKW@CunwgU9&E!g!Vl9MP5r76U>dzu+(ZOwJ@!s))q;(kbFq4fL<=)D_0i@c2vg{KRqs?>*Tedtqq>PIh'
        b'TQf5)RY-935!Hn$F-'
        b'`{1Snti4pQh;D7c+ZUvGBCyz0xx*LL#Re<@DZ%paTB&HuTZA7!_9^MCmCMW6mxU!Fx<d2OU2?&KFmSWXh}wnZJ+t'
        b'9Un^+ZJ=sxtDdkm+Y_N<Y=H6e*1DUJetYwcKH3t9sUCxl1w5'
    ),
    0x100001c8000: (
        b'c-nL7$oR?rgPDPWfssMr06POF;Ae2aCX4_H(Rk$>?1wVjp-Bc5H2Bn@`5%{=0|c5O?*ESiICU`8gIyWHz##B}5ko'
        b's%zJP#y2Lbs71mt%RkiS4c{sjSfQ2NFq4+5ZYV1d#cP?`ry3qWZRC@le{Wr$4w87+|TU$u(iKf|B^Loq*sxNHy%3'
        b'~x9e3ov95U@&w5;szi-0K^P}Kt2#R0Pz7qU?e!9s0RRtA%4C'
    ),
    0x100001e8000: (
        b'c-rMu-'
        b')mEM6hHUt!Q?iXEk#^uipI3m(i=2uODVmjG&N{$6KW`>ltqS!s4Su)GGuv4YN39KppQac0u5NmgTuWH^02DKnx(8'
        b'FGR7jqhrtGU@DIq#&i8zCYu}wu3miT_^8I<w_ndG}0Ki``MTo?n;0yT256=zaAZ}>2snsd1{$yo*z`IJl)9Q&<e`'
        b's|>tKYRcrPXilywgg(b?32q<IZFC+MUPhS9jh4rFPtTtY*Fh2m|y4&wjOh2>2h50bekKKE4~kSl)mjl!U*1#}kOX'
        b'$6;OE%jq#~4<b<R_T8?<0^ilpx>G~@`x@4-No-'
        b't~*t{vRbxUI5lEmU=iIuAotKUjYoR^sXMq=iI#Oy_hzD0?FC5hIuMEh%r^`wK1c?X**2U`mc7Ge$-'
        b'&p23#J6N4_Ffrv|dfLIvjDy)(2Yq7>2F4w<CLFXU9ju2<Y@9T)88NXnVq#&y#Nwcdl_3+W!zL#BOiUj&F%vW~8#2'
        b'*%*u=mQ6RjQ-?Oqc-UFv$L!6QP!l2D&${h%ioiL5Vd{j5~DB*42b|2ywj;2?dicexeT4|ML9&S_li)VQ##bCY_Ya'
        b'sHgfWT(ctU7eq}%F_nrX?OW9qnj^JWG`RvDfzM>k2Xa=bc&HuS&X)^nTp2xVXZXyx-'
        b'41?Q5+ST`xe#MwGHAOfu+3inOEXbTnEoX;v?0$DE=rkuP51mM0~O_&pz|a4Es6aq3kUC%nLF0?-'
        b'3s^o?)N4H4&wKJvY^w_M|$G=7}lx@2EA?)9f>EMhxX&P;0hE4COQTjq&)aYR$knk7r&PGSt2);@#C@L+#7F9%g@;'
        b'cyHq*`^+;z_Gi>L$%fcxUKn6MuD(fekbUM>51%KZ*0g*1Jj@e)>`$mQ(?{87?!H6H%hT~vxnopl)bFvJJKlA|C_T'
        b'OZFn%`qD1OCXim&Z#cpu;Y!MmOO$@{l|)9bM&WGoYrmnuVYwHcIUtEaZr58EMHWwHWm-'
        b'Gsvyy_3FNXqp~`-(JmQf+D?=$1GuiqDZ_-Sf^+ZZxQ-dpJ8C-'
        b'8QO#iiZt;oVS%DZyh>Q7Xb^8gZJ<S*ZqYHWUYF<;3f0rq6&ZdnpkrVCsCszihhKD;YFEW8t=hHmQmb}_Y<=u!`|D'
        b'$SH09QZ_>}qxKol(sn}SXpQ$0lW7`K18{l)DcZhvw6hudG=d>-'
        b'06iQXl=DWL0rcK`kR?Vb0)f78#7aeYuliP?6){=C0`0k5&D(*'
    ),
}


def build_partial_repeat_context_pages():
    """Build bounded generation-two caller products from source."""
    first_pages = g17g_partial_assets.build_partial_context_pages()
    result = {}
    for dva, encoded in _PARTIAL_REPEAT_FRAGMENTS_B85.items():
        start, end, source_hash, fragment_hash, target_hash = (
            PARTIAL_REPEAT_CONTEXT_RANGES[dva]
        )
        source = first_pages[dva]
        fragment = zlib.decompress(base64.b85decode(encoded))
        if (
            hashlib.sha256(source).hexdigest() != source_hash
            or len(fragment) != end - start
            or hashlib.sha256(fragment).hexdigest() != fragment_hash
        ):
            raise ValueError("G17G partial-repeat source changed")
        target = bytearray(source)
        target[start:end] = fragment
        target = bytes(target)
        if hashlib.sha256(target).hexdigest() != target_hash:
            raise ValueError("G17G partial-repeat product changed")
        result[dva] = target
    return result
