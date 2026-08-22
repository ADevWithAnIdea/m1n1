#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Clean-room code image for the own-source G17P grid helper.

The image was produced from ``g17p_native_compute.metal`` and captured
through its public GPU mapping. It is caller compiler output, not firmware.
"""

import base64
import hashlib
import zlib


PAGE = 0x4000
GRID_HELPER_CODE_SHA256 = 'f2a0320d1890b2f9ed4704ad6791aac0b289e68aac78fd9fee8762aecf6f9b2b'
_GRID_HELPER_CODE_ZLIB_B85 = (
    b'c-rlIYj9LYmS*0}TUA#jQ7@HVg@CIo)k6<dvJfC1Mun`#!eBShwLENQSItT-7~{6bjoe_|>#LHgBnylLvK!0TD~YySV2fzmZKj(Z'
    b'&qC9&Kj>b^V#oeidLO|!I>PPQjR~(OVt3pV(cW`T-dm~?lI^j7%uMWxKxCdgdGh2rC%-(Ic}WQNwSJuc%>Q^<vMYBcP~S1Ho|so}'
    b'npfB7)qT13|07;wqdciN7pedM`Tz6&lTg0i`e`^>5CsRA8&7G`qG9dc$`S3}UOlOCXj`VTgu!|f9mM%3RC{<>shQN10R~pS8F91Y'
    b'BZ@l7l0g>KsD9!k)k|5qkLsQ;SffQ#KBrr$H=WF7Fy?h66|a)qBz3DVRkWo+MJo&_+QU9Y+fbxv4|x>rLzZNy-yX)s7=xM{Yx_*B'
    b'd7Ua)#Pg-+|8?yrn2U7j`oftmGXMYPb58n`D!}0HOC6I+l5_4m=~tn|xau4BtGz6#vXstt7O=z?1~tz5b>`P(4SZul8`TOOan{b*'
    b'Fk?%3ZB4xbwFFZc+h|s!MT-($d$uHD%J;E7rAe+QI@z8`QcWbbvOSrkvn#RfA7D58=i1jZ-&eHS+#hw&??e}Z4VhTZSWqowwdxS8'
    b'aKZKjVYZ5k%AS9s`Zs|8ms<LR=fU3}qKA1E^K&-lXH;W$?ao;ww14FI#r0d%%m#I9?H+NF-2FiR7SpQ$3yOH~8tc+I#;&F~b@uIk'
    b'N1`2T3~OaD391E^jLz;)s8Dljgb3HUjR@bB+8&<rZTZ(s|2C`+w<vFtD+X47Y&eMP#HXY|Lcc(HzGOL}mIG01lI?c$rUctzxEX2G'
    b'(xF;q4{z<HvhWwM;y?lOsx=kR+l{^VD1?BZDgNwpaHx5mH4tzh5uysVCf&_`3Q-1<0-S?0K+-tW0Yl4Kq0aUdeD<$8ah)2hKxY*i'
    b')>bIVO3|Qdeg(9z<gLkAu><5)il)bI-;UR@NncXu9m&~)Mjdmf!lq$5n4WrZH2kbAg;L=$ESbs-OO}g{G4^q>gSpLciVr}0fBR_o'
    b'1hp5BnBlRMK+e#!;ZZ(}tshi0mI3#(;S(thS_EibDJ&a=PK3R@AGpjJ7f7xf)ZK;QB_>D+je+#jRtxaY>LX)e6I*_QIyCt@b>eX<'
    b'E{&fKjXBJWaA_(3N6QK-z=xq3rs`tjLH4oFq426l&KRZ&x`fV%e;YANxv7t;Ndx>08sSgjnchhsh9z@XQ6zBO8@e$PPD;QAt=Dtr'
    b'R((2ov6aKWR(TDFi~!5vw+6Os&Iic|tF(Op9?{uSXrmhVp@k<pHNaiAyGiW5`N~Jt<cB)G-74$J8j+A?uzHi|{)Gy2!E%l0{yBO8'
    b'z0oN4p10{SzIV!|H;C;cHr?Rchlvil)(MyclX^#lo-Id(&h4@;x_-}Y)=;@wB(JGVMsA(hf1BtpUJg$`+vJimw*Q>kjl#aL;RXLT'
    b'PolODyg^icxvwfy<6^pJ67}BupQ*q5*}huhjkI45zn*S%G56)Z`WlamHIMdHQ%lpx<?yS|Hn><|^$)_C2ukp(Y6bXXx%3Cbv?g>X'
    b'^DFmgjbr3G7Ih^3!nZ@EHfFV%*)|Q^Fp45$E}rs7ai+Y3jRjPc<`*jV06oLDjRt&;DT#pXrqxRWImN=*p+<4;;CSo}ef+j9+fx>2'
    b'F>n}J4$|mFR^lK#*tS+cmY$N-Dq-l-(xl6Xr0U|n?Y8|5(b*xbTG(@@%2UGJOL~TDJq{M|_Kaa&<|1`d-BU|gXsTz*=wAZsCv?8&'
    b'mD*GZGtT#z&gm7LPqm-#tKsKMm|5e#U<6fG4QLE&rV6b4TWQ^D^ZTDwlHsaT-~X(fO3km>{oPQ?RF(0R&TAe?InR4}Dq=t>W5B$t'
    b'_=P?lS7oYtSL_EhPF$7xs=Dug79=S!J42{1sTlb%yN-6|tKl-L+f{bWuOLUY(6Ss`BnMD+(K(hVb%3wJqQhimju~vXdZA8E6SNx('
    b'piU{!smk~<&@`YGQ}2Wcy_+LFDW@M=Yd}tw*n)B<SvP3%0%2)j3i>eU<8$jEhXbcEiEAq{$Qb08_do_m=o+-wIjmsloxIRx&`Q;9'
    b'eB@Q%1>B=KB&OI7=xfyd;E&F+QqF!1m<H5Y{Xx($6M@l8^6&056c=@oM@UDWT32<bA~554nY}6)MP|oyqy-0>Sua=$|E&>F?|qrS'
    b'1UcQ0jhUX84O0Ntorx}6W<o6g552&Oj8KilHqHS3IGkMm`yW1oA8ZBR48Se|5|m>2Yv;I_@oLP@fA{rc?H`))&ie`e6Ucvkuy?ZC'
    b'?6Eq^5m-U)&g;fn8RJyzsKlC|sZewG8)n&cD?i|J->^;+xLcGE{dX$S!M}!RJ*7uokR^8f5KcF=zp1Bmh&m=(`Gpb(>|+7Z#9<!;'
    b'S`hFm=2!TSqW*Lc-04b|3O3tyalGnBBqN40Zau%IqTk?J#rU6<Nsd$cMDeDjrZG|6;PLT`B^%3_Hc{MK0)2v_=Iu^_>jwCCyivM@'
    b'BC)}(-j*oOM3WYLufC4G_VVf~gZ5xRxqhQR4JB@_Rx%|+%!E-_ni12*jegR+fyHpWK#6JUO;|6WM}r8?=FE#PYZLvI4puP`UTMma'
    b'SQErQXP{N1P~Vo;s1xP0I-WY9^<b$&85aA+tlt4`5m7m-L;rdc`gAwTKJu&*gN*giKsbsm$re#=wG{F0^|2CInXo^kab>au?Xn>K'
    b'=7nOE858=f4()~lr<n=OYIpPQH3x$Vj8$u*_e(J+l&v7YDR*Qh&qf{v&Oa4d`Mk>-H-zI#I@AI<%B{Ikx>{fq%0Nw<4$<W%U8x2d'
    b'uHoIYI{e$n_s{C*rhBhKMq*MdH4A7t7Jo$Z@f&OL_pwVy;!OK=x^I=q&P@Pk3Zw3mpSZ534W8}sc>L+M3}C0J*S>ya9n&Z(56<d^'
    b'r%5&>lM^JtMx*y%b^UY@;OR>BN*LpMxNTJ$Hi3$nBM?=!(|uJIXV<L$){k7TW&+$aJu{eF?$?hVV8;idS7i=$rn)Vh0k}7P!0$m{'
    b'UaUfiQ1d}1*Y(lGmJ-lLf%vb%o(0o=UXZN-ZxhxJyd13><UCQ~U#Y=bP@q>i(hsdzx6+c>Rk5U1K)FcN%yyj_sOpbQ!NxR2Bj`k#'
    b't~LcX0{~|1q8H^HT7tii1!4ow_?JK_N|JDmoLSaZm2so73zn{{pD3=VEl^rZK$aUvYVWtDA1hlIg_@MCq2y!U)+GTEFC1_Kg(GFx'
    b'sLc)XIj8t}Yt-uFMvg;Ttbbo|tN)qO*l6fP4mW6y+5k;*BN$^81|Z6Teuy`m(6C-4>oc^*XS?h<lQqg`ySM`S1ff5(`okJPEgts*'
    b'-3N4!MfdPZr0*&OdXcRi>cN9Z{~j+;23P^^1s+0wg-zM$Z{=b^kA;Fp%Ec{YOi5&%Df@p20h<;@z`O21z%^M+ac7Z_iQsP~@--qV'
    b'5~fN7jHhU?V-oGC=OKx!SxkbKR*8dzZe}j}@q>s?h>s$8TjF4yg@X}9sERp+I%pwOi11CzO5jZ}hQwmRwOoA6Mdm#GwGj^R)Xc#_'
    b'#=EUi+;jM7W9mK|6={F3p#7Lo@$jtvUtY~Y!}a3Gto|wC;FULzv=I(&AZ%(ubPN2f_i8%A(Tc6&u~~h?%e@vZ8Ec<zOUEb@;oLH-'
    b'Us;VZwmom-=f$5KSxYDx6FZ=Fx-Uwo6cL?>KDX8(w{iL2pJkQ<@`Y|)YT3ZFt<!zArY*7Slhti&Gdd_*`N28Y#SCDn8F*`HTWtnX'
    b'Xfp_0A;jg0sD*1mu@NQz=2;s#3#yOZMeC$#R=>3rF>|7-wfNTSElUY6OGN|ne>%Oo!j$VjHrsXJTy#a+#}n=2SrkNn6Ji1_2dyra'
    b'(71>f4YOTWv{><t@Va;u*HHtml#3OuCC~UR9>S6v%Ls8xk^k|fZ7T)=CHGYTb`h4gXVL3GF<?lkjkoP5az{nP;uN0~-gWiIwAhJf'
    b'0R86BxBav&<;?ST31~SIfS!ZqWFNp~kaT)Z%0wXcJYglRdBU{v987bIpp|!&T9_F?8E{5}c{Z?*;RNw`i8Y6yjgNxxG35t(0O&p&'
    b'9|5O<{_v7`356;HDZneG&`B@Y$;y=1l{lo4xXZ$+z%6`1cGG`a<|I0{ANSh*X9yu=`w2n4<Vgv1+i{_cZfQkjLY6$dJSIy%I7LEf'
    b'9zGK?cOQ}0bX-}PLhRD}LqeF5ei!Ttkg4KHZ<pkN^%kJ~H?7L`#(3*VSUbBzqUIFlXAonL!6;U=AtfLhIwb|HO}Gbf-g?rH=WfUs'
    b'60)?MS0bJpOL|VjxPYiY)48q!t-a9UrCR}WgFJbL0u{XhSES6%@D5F>9q3U^dE)KJ;$}>AT3FKnRKQK(T56*sohtX92Mh(y`?8#M'
    b'{5cE%YB(R3`P(MtbPhrq{5cDe)+o>0xCga%<;+~IV?Fkfs8=!2Q$o3Cr|7^@pkADV(Md^_`sf#n(N7Khf~7@WRtp0qW^u8ZU$C@j'
    b'RDPI)i*=-vl~Z;!D-$`{VvGYuZTRKP94>AVCujAowU5Y5>pt<^tbVBf?OLX7y8;Mjptp}rU%uCrywJP--QNG0>45GDKn%b<%Eh)_'
    b'g8l{P-rkHkUk-Oy`!9R{eP$!?GF#`kKe_+uZ>HNhyK(O$fCnG79a1dx?E2{LqwC^eZE^HW0y3b@Pk$r5o-@>r@hfW&E#12IXzi`P'
    b'?7qr0;A#~+h-<^6)0s_-n;U_)MjU<vXdhkdzQQ!xHxHv_+wXpKI^D{+?1dcL*8b^P+$Y2i$~FM=t(Cq@R1#&QIE=Z&L+f5!Mtj0@'
    b'l!I&%J3f{<$PV!elQ~F2JcThE#XaV+=b+CAKkM~p5}?th8I*IBkmCWNpVBLKPXCO0JokH$f<5>kjsmm?g^5x?@^<kOO8(>uNO=&X'
    b'B(D7GJKySG!*P$<EuNa~DtPbByFY#R+gCn%?}@c$f@b*?O8MyS?H=-Chd6RdztQ%cZ}zux?bf?*?g3gt96qVvxc_?(*532ZH<)%~'
    b'-C^Jbdw-*#?VZhJE6@~C@W#5Mn=OmTJZL>X@-gN?3ht`6Wk%G&kF?quQGy>%P<aO9dyF!X-QvQm{`YeK)fv07^^%OQPS9U}{mmI`'
    b'=lb;dBl~FYOd|i4J;-%q`tnwjZ5@Am57UgRy|>a0eCp72-@l+;wMOo$sT;kQ(k&b#ut{_w1!O=QSsEy?zioYbWu_UTv@y{3^u9El'
    b'*=xfXMaQZSl~mk?rP}z>@V=FYisN|i*@=-<QGc{LjyIMaSUdJ=_a)FE4w2IU=YSt|zfMsHqr8z&Szsm5>nNfCZ;%qj{EILoiYF#}'
    b'Mc0UpZ-B42g<mVfwJZ|DP$O-}PU(MN|EJ3+Z+nVju2FRU(C)w2ii<`u_H*bl@!sZFp|)G>$0%8WNbwX(+Vv_#$!>^}#uaFb4s4}-'
    b'EeU(?C1`7cHiIN~qr}>uKJl&o8j7VRu^%$!_x`N@*t_4pRJ-$dOBDO<C$8{e8A&ao<D`D*Cr^B{zkzGV-hJ~f>X!uC{l_1eSoPFu'
    b'rX5;|ytUz@tB%E=x{D$SY(!^|l}F=bmAzIZfmOz2B-Qcc8#0obc}F&q8hJ8dm)pf-iQxN?XXCxOINI8RW#i)IZ^)dR|K{>$S^B{2'
    b'`IXGR|Jv-iB1<2befOjjL+rZQw=UBG`S{(x-uQ@>k6&+nWG*uYeE1z?=1|%wj@*_xdW-06eFZc8_S#2B>4jpWvF*{*R9Z8M(Xux&'
    b'i0vac`c_FDQfAL(Ir5WN`{FjOZ*}^vA@;c0b4j+Pn(UDen0+fVanP%gJlSy#Mt-~@+q(5pFO6o9Pm@2F8rF%uQ;>}Z+8*^&Ytw<@'
    b'UfP{`os=?m0bgh!VuEkbjrjr1YBxyha!IxC3NY^Y-dX)aw0p76b}}|qfwy)IR7+U3I;xpg&7j&fs}_^}6j`g0{jfHP`7eKAxI}eF'
    b'tA&%{Ya6|tu;c@OmveiV{rv@ZgVuHYSN<s)mfsIlj%d+dJxSMX6-<HL<)L(Rh{xzWT4>+OZBrHXA*Z6^*_7V3i5pKA^y&r_%ADv+'
    b'gB4YfrD?e89?mHE9_|#ua>#S!`y0J{!_Q{biM)Qu$clUy{MHM)2KK?@Iv-f0I1<O51u9n>ryTr*TA-fe1?uapK$Z8Ed`TEQImC6d'
    b'z93qdqF29=Lr}b!^!iw2a{5B0()t%~U!ABWeSKh^y#G#GqcEsw8v=^v_8R^)-~U&fQpd_d=;K6B?X<pF=qA7I>>>#`#`AoZG0ltj'
    b'yo_!*<;|{~X_Db9z|MXK*y;8*D}&dl&)NJwJC(UUZpYlK8D*DynVnsdtbK|AS(9ux6KaCpj2m=j6dL5ODi>h~tTV6(oe)|1aG9cl'
    b'G^Q!@=T0%^`C9RFt^RAqpY{Dp<tZ(?e^|TsFn+(1NUDx(9QOK>PCCKLuUT~Ymis4z){Sxza!#v4Mv+?-VZ?2Nh{01h3+fPY53_=f'
    b';}A8xs21X)?11rxV7fxFq<Ha*i?4k9?PP@&(WNr#a_+9tyHoUCh)=}GC#S<@h&Q^4>m=Lev)T%+HtS^?JgFxhyIHSUUe$oho$FPV'
    b'bMz`imJ?s#A#xJu*)HZaBWnO9TMJ$B)r_)O83A~{aR;jVorD%2TJQE4Z!!CQ{ui}Yd?l^;(h_w45yUw6o0^Qa<s738@clzyGN^cU'
    b'Xi>*}^i2z`2c-b`K4iN&w(XpfZFa;upzR?jy`wx#@4vgbu%!K0@gJQ3(?usa?dXMK^qeYZ9q6}b-JH&uKj$jWpD?8eOUEIVdKmt`'
    b'RDh?SC|3<p?q(nR6h^O-<(geKM5X5YU%>*fOgHTHW|9yGZy0uz;K?r-!1*RrScx#Jm`|=t`~pGQ4JU*h@_ZO0t}cr!=(AS0#TA>%'
    b'<udcQ6lGzqseD<Ba9zun#TVwfoiA$<F2#|{<-qk5dbZ~!Y2(0Xk10!`QDJ7P0ZR>f^Yb*pY4kwV>Lqd~rxRa!>oA_5cL(JN59<Z&'
    b'xKUugi9PX0Ygen`x$)(a@r3~o>)b8ls|eyt#fY%KExA|0Z%Zb95b@g+`g^j)ql{wY1?a1j4pm9PDURVcBcGUI(As<5FzMD{qt+2{'
    b'+@r-utuGOVs|PtN<McWTv8T~HrxpLdmD?!rq&U6kS@cs9rSN+e*%#?=nNcHRF6a8lIfyxH2l<zh6J%?GuV>eMe)g?YbRc{8poyT)'
    b'U>)X-a7K&6?p4MO^DioENfJ;}MhYkcM3J|{xp%~Mxtf;o`Cr(~8-Hm2_`8OqW@Hdh!h}*LGT`DVH<VI{KvpSTCQE~n6w*MW!AJ&a'
    b'?+ntR*Vg1k#kS30p3Rz-J2d%eDmt2@NrPpHOkO{026tM>7y)|>{l%QEH)S~o^Egv-W;Q2kZVW@;exlrI%T!j*aGsou0X8sFIV0}M'
    b'<wUDfo7|h5vTY+$%DM7dY6D3lXkkmE-0|<!Wy_a~AM#KNW!kX=ei^p>vY71uEf$z3+A$kT`JM<W3+XbtKr9dD#o&InaBR+5$XZ1&'
    b'4OtpXD?vo!8ko~rdJZ%Gym>sqa`Y|B^B3@@EUx<&@GAPLVZIM@{4^XH$kAXiJ8Id8&*aUo`zx%yK^$@6wMQ$C*4{hmycL&XU&=2u'
    b'&X6?@*_Naa=dAYO>>9Vn9?Y)$Om^L8taYDSAiktVKUC(~6fH7??@*xMP0;V1XYyvyrOaC^mIWXDY8K2#FG7G6X`IO$^><kmACcc{'
    b';CehKS1^wL@4npV`FN9uL-R3xkPs`BgXt#WP^dQFew)|=E0CgJB2ZR>H)CXIR|pj>jwE;dhBH{XJcG?RAUAG$0B@2*Vp9yxS1S}d'
    b'TfSZa8c)F<9|EqB2ohJhfULMg{Y^#O`jSufJP19b_{AU`rfvpQd>OF%LPo0#)_T$xB*`oWz3JOTEv4Sn-Rz-4Thet$+|>Jn9OQ%q'
    b'95HXoZ@xgkl>MEYDq73wHSqnRDDhHz@SuDlBtI<&KUJ|$9AQ&t&p`DGUJg`+g$fJh?fh~WLkMRp?e%}_X&hQk8Wi(*gVcp03in$p'
    b'uPnkSBV@&hDu#1{g&u#fuyVq<mVKLjjoGx}EUh_98<e!SD&i?S_g5>RMr&I)^WxyaY_G9wFIum%SDxIdEXNqGg{<7ENIFOEoom(7'
    b'HZ;-v$I?5rZ8oz~uSGI*Qrieg7S%SI?Nt{U4lbl^ZI&Y%c_v5O+Q`Tv+R|?WVkG0lxN@f#uy}d_i>GaipK;_`9BQ9u@w9Dm;9J<@'
    b'Y1`t!kz;YFeOZgA7qEERwm8VivG^Is=UO~%TO4{VZ1J>hap1_YIMlwt;txrzTftc?3kHL5TI?ds#}vI@-kYeHlSdhYbDdr5)tNly'
    b'=~z?fTkz(y_L?-#hDT@}Iv*c*m>Csm?(rVWJN4s{G^b_NJ|1q1m`<+uKRF)G$kzAA!<65!;a`u3Q&=*+q4AzUqP-Xx@5vBNTct<O'
    b'hv@Nb{djm7`!ZwI3u~QjqP07u6w~$BXB~qWQMw7ErNY4X<XOoNr%UQt2Bi<i9jTPJ1WMm?#)q9GW5al)KR|l^>V>r)Io6XyVVZ?m'
    b'{acuArX2e|2_w`1&WDEV8Q$~4T21P49md2Hm08_>Hk_&f-+yv8oRR(3yH-kBp;exm<?o-hby?+%R|cr}`^DjuZaO$x7B#<)eO)-h'
    b's>&8;onxgbdsI8)A=#r^Z8JPpDekdodYii3qBUr%%G*>qm+DZ9`s=cAD&r&><t=Kp>MbwT@Lr@^k2f*HlG9&l?}#e@8z10%NX0u3'
    b'FX!2K*i6x3#rpMf`__u0<NnPU9o5U*tS?}z0bK#LT|z4&e1@`9aFuW!%GI1T5SqhyQSonfFu!VKq}2@*aD4^$)KI@>r`M#MMaA!4'
    b'`2(%g3p8)E-tzF<;w?_v*Xb0iJte<(RmB!JQU6wtU#+y?j>BS$ho~a*-K)!OszYq?(P+iScLz%CcWOgyZz8H-@rLZ{wJNk0``cS4'
    b'{)REyGsEJ();Vei106_$d*d9H`7F)28nfTOf%+Vy7itIJGA2v-sS1?Nm&k8vrc9y6f0@l!R1q6wr6t8?bk1W;XiWAMJW(V|Draa3'
    b'_Yi(>g#S|oz2wUE;CC!kaiO2fth+728;9JsTnGNAi4y!@FAhQgAN2;rna8Crz?DU~YVH}LM|ZXm2fgQW55+~mv?Bob<^YRJ&vW-c'
    b'&NoxG)*?@9wQ(Y=56AywK>F}`TIX~57U0TiU95U6-i0`3F!SI+@NE_2Db(7_=}TgTbJW_)Q}_++omwmNZ2eb!P9Jj-t@F7OpQ|<Z'
    b'SiB2yxKHG0WS{2>b2X~w-a2(5Uy&a1IyUEXHp|MC#e6=WS6L)JLLU1o>-;;J;z3u9CbK!!GgO*4qXO#hK5L9*=d#9{OIhwMZ87&6'
    b'0ry<bDz^C!AA1dre;x<O{!hhnpI<&tQ|r8lnugr6<Xl+O@de_bIM?c+hi=JGJ)@<08g0$mALgSo{<&PadLOVys)G#JvWMNDd!O;R'
    b'7ahfFo6~B+QSx%3fc)OPGTtxIKg8x)>kraeumXqVZae2;LM_fzzj}w=2D5higEgC6TRygsEn&4xx-Bc&-lY+8R{Om9T2TUPXVUXU'
    b'Ry{o5s*8@NFESqUPL#Uy`M=P<f1aKFpykVK-$k{~zf~!&%edz2o1OV$_W8eQhG5?'
)


def build_grid_helper_code_image():
    """Return the executable code BO page for the own-source helper."""
    image = zlib.decompress(base64.b85decode(_GRID_HELPER_CODE_ZLIB_B85))
    if len(image) != PAGE:
        raise RuntimeError("G17P grid-helper code image has the wrong size")
    digest = hashlib.sha256(image).hexdigest()
    if digest != GRID_HELPER_CODE_SHA256:
        raise RuntimeError("G17P grid-helper code image hash mismatch")
    return image
