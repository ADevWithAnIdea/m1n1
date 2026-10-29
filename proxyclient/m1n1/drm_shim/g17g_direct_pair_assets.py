# SPDX-License-Identifier: GPL-2.0-only
"""Hash-gated caller assets for the earliest G17G direct pair.

The four bounded fragments are immutable Metal compiler/resource products
from the first possible one-triangle pair.  They contain no firmware or
scheduler state and have no runtime dependency on the capture.
"""

import base64
import hashlib
import zlib

from . import g17g_partial_assets

PAGE_SIZE = 0x4000
SOURCE_MANIFEST_SHA256 = '62529c8a383500b7ce16bf55eddf0cf855a659f8cd743195b7134ea4a8e244b8'
DIRECT_PAIR_CONTEXT_RANGES = {
    0x10000000000: (0x2ec0, 0x4000, 'febddce5bffad42b568c93e07f3cf49ace03fc3c90d4c4beba9e05701e970671', '0b08a3ed04dba0bafb9384398f07996c856f5ee16002a2e55476ebf813f7aacf', 'dd238a7ea253f55fb5122d8bfd87647f9c004ab031648cdb057d43cf56af0dd9'),
    0x100001b8000: (0x80, 0xc0, '2fdd53dea11d7ddc17c97157e0a055ac8bc41ec81f6313fb0371cef3c5b3e957', 'b0c6c621e01868244fe9b0aec2e4a6166b0d458f40e4771ff4632f6a9cccb43f', '59bb079a79e148014792d6cce7a1a866f1bf24adb9606882e144d21ba7124e14'),
    0x100001c8000: (0x140, 0x940, '4c2a843987184e92d201a3762843bdd5769200dd59756e76f458a1063e170c91', 'c1679563bc759b61f91e44a07ee444ebe5312d6391da9fecdf25a547ffcb1efc', '290488e5db4fecb2b06f0738bf4ce36345fd6e8bc35f1371873f605cb862281f'),
    0x100001e8000: (0x0, 0xdc0, '06dcd9b8a4bb71ced4d4236f9a5e547029571b58d3d3a7787b0aa72b094efc57', '96e3a2e96011cf0bce9cd8f5001ea7d4da29919e4d194c3b1d4139706a7d56a8', 'e389bfc84809701c1f37c7072166502932656fd059f9dfb0a8f0c7023b0c5c34'),
}

_DIRECT_PAIR_FRAGMENTS_B85 = {
    0x10000000000: (
        b'c-pO1T}%{L6h3ozm>q`gG95vN6?JBIcYxift4jo-r3=-{3TaDPQY%`in*M3hn)qUE(wPCJs1GK-'
        b'Xl$Fs-3FC3S}`exM$uXo^}z=pB>G^CiKhDCgAXQ}re|h%*;!!IE(p2#?mg$s`R+OQyLW-Wto{<3%vVye)B6v!tZq'
        b'Bh^0_P4(tG0=JFx#0d!=odedroxox!@km0Lr7TL!E8dLB!CiJ&-'
        b'k$qQGM<*`KlAoL1|fgngwp(%}+($&zT)2%o<4V~VFxDUq>oR1)0$8iVeFA$4*F3|Ig3v>fwD~?W_??T*%;|R`25U'
        b'=C7gY(BQ=6iv2FBEggN5Z6-'
        b'nCM1AW)}ZpaPC!Ne|WaGQEcaj6x+I<VjH$lY;YUJ&f7t;Mc+|uEmc5d>Q@iIry@XQYDKJ7$|taPpTOCD9B=n=g55'
        b'_%yN`IRl{=5~8=d9(zYR{JNU<6Bu_DGZu6|yvWq<^<lcWkN+4QWuzs8|KVSf#!L9|fqmU#oJix33^3U&20ooy!Nx'
        b'>~H$%_Lfi_6qcuAud4F)p7&<K(El%c?NCHzGnnz0+2!cni1$Rjco!kDr0;V#(NP121Iq$Z+*vptgDsQcWiVK`f4y'
        b'{3F2}CzSPyFR*Y+>u7<4`S9AsXA{f(v*la+buD)r-'
        b'@P~EvEh~nPu0mfM#;its*MQ@?8tpb?N+dX|tF2a4NwgikYcc8r#B~OY>1v0SNgUVJkE|H6dIS2l7*M`(xkLWUfPT'
        b'%%NzS-'
        b'O6n_Ak1?@LTu7`0=aJ`Wc*mfQ^gZLgJxW;+58^pI5fp3!dUqD>K2qj~Z_!o!^89{6h@ee^PX69CmpAwx=S6h&!-'
        b'oh;PzMiFCIZM4w)2MfEO1-*Wy-Q}SUeqr&JN;Jt$TPlUC5-'
        b'DQUiIlzq>74hwG8d4hJNw|B>_b$+2pD!xdJI5!ypH+CL}_UA=C3TnMUgxnHuyYtzHA~gq{$>S`z(qDfl3!Ko@lQ*'
        b';1&9m~*;g0Hm*ElFk)3zcLbJNJ}Dm_sWiRPRrY!5G*euGM<p>!GMjiC!tu3i0Hj07Yx?hyt@<2EH5Hv{#$0!-'
        b'&&dXBor$%B6>NwH~np#IEmVuST+Pn^z)_o=EoGutVJq?Go$95?(j$EQ$CWa5$01h&9S3qjegibC5&YJBD9~mn2b-'
        b'K^619do!>&*0d=ke$D2UIRS;_l;A<3ipm0M8(xW**qJrH%y;g(z0Q3uW2GoH0YHM}h#JSP)4bC@;IHy-*us(nVK-'
        b'}k6k1R;$UXR+?ag1lSp*B_?=T-Vo{vFiDw=(9587Xb7!<9$sHdnPgcu*U7Vv$f4{M-'
        b'fZUW2YL1cS6d5yXKp>O)6Kk3Il^vlD~{!&#~MV@`tIHR?ifGTQq)C3zM@jA%U)?sM><vYRUn+IP2WB-Ogp2mKBeJ'
        b'(7-'
        b'RWULMKbHwnJ79CV|CunnnbLJFa8SZnzv#I!#w1XGPfyjA8AlkKL$4+W+cA_tumvWN2uDEdV`~c8vQT2jU##yR|;l'
        b'*au9*pAAH(m{Ku8Z-'
        b'*07VbuT#$$lxI^B>1j;x97W1l|DQ2__HoG!3VGlngSXs)xv^`_Lm9aPShcou8w)luG{*ukkm#6Jw!zeRhA7J2wpG'
        b'w}ga#QsJ-'
        b'c9qic}z6#WdiRde?QXE=!m#K*&J~<hQb+!%Q+Y>Wf&?=29jp*nhbc4!zKfwd2@V|7_u^5o{}k$l}SluQmjnPnM~<'
        b'nWwdwYMvgsSox<eFViHnJg2`mQR{YT%UAdWq;l`xCPcXz&3_~`CGm{vyGToe#iOb4FhHU-'
        b'C6AbW5c2_2{N;ciy%b}y&IqJEU=P6I@VoJyE=3uy;cgK_*9lM)n$CSw(v-'
        b'aH8nc4Fr+ikSh@*qbo_wv@)rX00A$oqC}%G5HY_fK-'
        b'{_t7is{gc`DK5OsWGiTs+;oj3PXvC)EmpPRDEJv+R^FEtgN`9V$;n^$e=JQvgWZ0hRBA4l6<NN7aJcq*n5STk%Ei'
        b'Y%PKdY8dI@3x`0XmtH#f<Ds`aj(nnDtEjuG;n;<d}&%|K}Ox_*F79m2r8U!TtY!f4y$ozHO>CRX%M!u1r1o|H@`{'
        b'%x$|zlNidl{8jre?8fw5'
    ),
    0x100001b8000: (
        b'c-muNKm`p@%nZbgKs=#A8p3E|gwSXJ0AF|lwE'
    ),
    0x100001c8000: (
        b'c-muNU`U8&XTSp*?1wVjp-'
        b'F~;ff277H2>o=bAUiI#Qpzq0H+Rydax@a7#IXTFk)zj%NG!k?;s$*fPnlC0`eCK$iE;U4-'
        b'5os@*n^T2No#J0i}7Mv;dSAfzlFCS_YvVZ~D(@frS66RSf?b1_c<}`H>JXWDsC5bO7Q8AU*)Z41z#D5H|qv0YP9S'
        b'IH9OlXdBHRg!0Eo1{xhm<-Z^k3tmhl02Ks`Ob%c+NE4{c0hKqPvIbPnfXWydV$1;o>J<xY5DYBO;Cvzg0Bl6JsQ'
    ),
    0x100001e8000: (
        b'c-'
        b'q~TQD~D_6vuDA98A)7wv;eSQ(SFCr74=VQc5Gz)}l>Qv=otI#}JWC>{z9YA!dxU73#MLmBCQVV8Lcg?4Uzm#_}+&'
        b'Mf){HrHBk8o5*0pJQRG*%l`MAT$^pMhq<S<T>j^Gl5=y<ckj99Ye`s2sbAF|D8ZViJL>l;wcvuStTCZmLc4^1W^%'
        b'33l%}Ub^FmLA#)N(n+9mYZ#O>4c$iy+NnmDG1CXVU8iF0dOF>y>?o0Mu%s;=?C+rt|bf8ueeH`r1QoSRa+CtRvgr'
        b'LC$`j@yaqx2Rd`d_ulc@~N=O)K-4v^aeh5D0If5$XSPSAJ~-t(5Av^n~LK$B~RFtde5f0lQv~f*%W)nrjd7T8a-'
        b'xH{J2e(hiwWRu_-icQ{<>kxq&F<4@Rjl7^UJ+l#;zsO6`x*Twj#3{ZWeTiPFg4D2;YSDc%#M%H2^4v_~n_5v53Hl'
        b'yWUT%J1}1A?%}KtB;afeU#efqq!YE$~OBb*5IR&%|04!^ijOYN0ojb1>W>gsLn@`dLMaebb9-'
        b'g$7*U!Tlx{rZtx_+;n|_ZA2qe4E#)oS|CMKxY6G6u)5Ik6jO^W!L!yVPMTZ{9-'
        b'VDx&9y}yEP%Ya3K=!9k@6$Ex(}UqDR<mE8@T>h&ud`nvH9--KpsKc7(;2I+q=mum-k_RJZ+n=ribLJhW{F*SSbul'
        b'=8tjU|kqPZ*d#<mWW|ik6?AC05H{G<v&JD2tGVIR$LH4sf+Qt3^?521R``J$Rvj05n=G1=nvmNT_#_xJg>p3HxdO'
        b'c#t_OSnqo^xa```IppUD|(4&sl7BX+PVQyZQSk^_+or{yy7tJ6!sA2VvJ{n_c>M+0M1Fe;9Usekc3c9&KcQmwqPk'
        b'Cib(P+{*qw{Y+BZ*w1#Tj@J{`b4KcUJ#5Ds*x#Y&9NEl%w#_-'
        b'jzT9X}XDZq(Q8|y9#Fm=vuJnxy7yAwjT<&|nD&04|a?ShAh3~xg2EO<HR&~qk33b@Lqhb5R+z$I(q0!ES>YT-'
        b'(y4QqRI_K1MEwnj=bJCD#+KU5G6*)ISF^rMP35r9L7%A9UXbvL}y9lj3cbfu}w<!XRVT{0zLz5UO*jZ=}BM-'
        b'ZvoUKLJ$fBZMpDwG~(yEWHRAkFDOI4KBkFJNMDzz-PRH-VKgi5t>SEy7Wi|hAUd41e#8#MJ{y-'
        b's}uR5yh%A{bb4uf9X{9b@hfbHAAT!`v_C{xJ88+0TuyRwBRBa?4URf9)R)r5@oP6Ota`-'
        b'X$bG!p;4oq0}SX^FohJ9MdBc$FyqV_Gx-(;+XE6IHna7$FywX+?tk59MfGB$FykTm=;W2Sr2s2m-'
        b'j%^AD{lIKT3YqT6qt&=F5AaRqBtAOx)CZ546_Gd!RL6-'
        b'UF>te_SzfOv@(Dy?)lLzxBs2%ze9^?^`ea|IK*{dS_m=r@wA$vqXbx<|VWl%sQ)Po<M7FTB6|R(0VW{co}MeS;4E'
        b'&3NS0?`$5NHK34F8jsvrTuj@E4EBJ<v1GCPm>MPLJo0cf}Dzp>K3jR#58_Wv+T(29<ib_AL<520W;7J_^W(A*;{6'
        b')dzlD{bCJ1Y5$f{#o7qTqhXUlcqf`HNz{PRU;s+#~smf}16OQE;o|FPf`z{P~TJzfj}&i?xnFNsd3Y!ST;|9e=jM'
        b'@y9-KXyj9eMwR1_TaF*^JM@2g-}&;{0`8+m^=)E-'
        b'&#kV|B~y1)s!*vrS}U(RDpjb|9hEBdzKNS!uRB^RuREGAzvF4F{Enwmg)W*n_xigvl`2&375ZiTjyg}O=c{pEVOP'
        b'+5>4|h4(V)8YT=&mewFz~T!TA;iuj-'
        b'BnW(A{eGC1F&;04_&!K^{G>AH?<vqZtVFXMcRg0JW}Fe~_~jsvq|KGaPH=UWtvy2;>ti-'
        b'OPU^@3T!lX~4?R?K%w$6-EJ@VJfxvx1LG-lE{+^8O%-`=Vd+7X=SV{-WSc$zK%QBl(NszG#;GMZv9-'
        b'ztKxCWj*q|@!Vg?dPTwfxm>17z3SKQ|K@%6Eq*`38<o{ldSCzNzdrzZn|!D'
    ),
}

def build_direct_pair_context_pages():
    """Build the four immutable caller pages required by work two."""
    first_pages = g17g_partial_assets.build_partial_context_pages()
    result = {}
    for dva, encoded in _DIRECT_PAIR_FRAGMENTS_B85.items():
        start, end, source_hash, fragment_hash, target_hash = (
            DIRECT_PAIR_CONTEXT_RANGES[dva]
        )
        source = first_pages[dva]
        fragment = zlib.decompress(base64.b85decode(encoded))
        if (
            hashlib.sha256(source).hexdigest() != source_hash
            or len(fragment) != end - start
            or hashlib.sha256(fragment).hexdigest() != fragment_hash
        ):
            raise ValueError("G17G direct-pair source asset changed")
        target = bytearray(source)
        target[start:end] = fragment
        target = bytes(target)
        if hashlib.sha256(target).hexdigest() != target_hash:
            raise ValueError("G17G direct-pair caller product changed")
        result[dva] = target
    return dict(sorted(result.items()))
