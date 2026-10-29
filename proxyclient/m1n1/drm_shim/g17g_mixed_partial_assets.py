# SPDX-License-Identifier: GPL-2.0-only
"""Hash-gated caller assets for compute-to-partial G17G work.

These pages are user-space Metal compiler/program products from the clean
first-work mixed witness. They are not firmware, kernel, context-0 scheduler
state, or a replay checkpoint. Sparse control pages can be replaced by field
encoders without changing this caller-program ABI boundary.
"""

import base64
import hashlib
import zlib

PAGE_SIZE = 0x4000
SOURCE_MANIFEST_SHA256 = (
    "15562b374d65cc7affe9a27c5b4d9eedbcca79dd081e76ac665c1f629ac755bb"
)

MIXED_PARTIAL_CONTEXT_PAGE_SHA256 = {
    0x1000018000: "438d73c0aaca30cfa90fe8975c24ccd2ac9fcc5e1a03a789e9101cea1a07b23c",
    0x10000288000: "45394f293e8ec2e532a0035ccf2711cd22f8df67469d743eea5e043629028173",
    0x10000298000: "6a3615d256f3f9bcda0ae9607d116257d85ab61decce08837c8b103e60109b12",
    0x100002a8000: "25a7974e2548ed6d81ebee2028bbe4b7f5625c3c40f07f583ef3f42925751751",
    0x100003b0000: "0601ebfc140b6b920673094299fd3c679fb4470228cc3d471cbc4da7a26cc32e",
    0x1000048000: "d394dd3bb3448375aae5da9ea27109575ae6c62bfa07a5b0ec3dd9a70f8162e7",
    0x10000234000: "760cda9fe5c72b6851359d7ba35e5bc4bcc7ca9d44712e9d598b3db5a64c5fe1",
    0x10000240000: "17e8a39a95a6be6b846d30bd5ee792a80561060e634ad07ae533493386470f45",
    0x10000244000: "070c718e81e58a00578b4d382f05257c12954e5c446d3f11056e4d23665a8020",
    0x1000058000: "d280b32c8092107041f6a97a772f31d231c775ed62694ddabe0284ae0f638e7f",
}

_MIXED_PARTIAL_CONTEXT_PAGES_B85 = {
    0x1000018000: (
        b'c-'
        b'rmEy9ok86a~=hAFRMo!Pp86#2SpOK)YDM#K7FZ(9j|_urOz2L2N<JVVKMN@G?%)jFLq%>+)W5m2AqSe!amySuXQ6>V}hKekw(|v9'
        b'4L(u4d^Uy82vmnzWa)G)Qi>?kA6Ko@V&zKR<U~$98*7FF)D<000000000000000006+Bdjs*a5o7'
    ),
    0x10000288000: (
        b'c-rmNJ8r^26ouhy5``3zu%#3fDO}RBf>_=LO-jn_AQOS2Sq3#Lp!5=024%{mB6qOGBQkSokVyDH>Bx^`KzOd~+zmt$k^H^h{#N?&'
        b'clYZ?<W(fCy2pEO^fRMh82!@dS4OXYF536ody$?LZKro$Mv;Ep+}HVBWG$D#J^$_fxS^ynEHqA2X(ZEQjnh<_u0eTleLiXCf6Dxy'
        b'W&Wqz`M-?uXZ{c8|D#@?^%13)x6QAI`TtB>=BMes(a(&2Vf0I*Um1Ov|5)E|@2}m!?>!f@&TTX&3J-'
        b'#$Q*8Fbhwe2GnpE=`mO}G%%J(Q%2>*h+tE2DJ?J)oV00000000000000000000fUEWcNC3Bb'
    ),
    0x10000298000: (
        b'c-rmM!Ap~I9LMqR^Z2Ft=o%tXvW+!$Xt<%nM5K*ebLf8CkRcJ$A|xV$9qhh?lcM~&=pXR1n1^5o>C|C|1$hV-'
        b')O{Ck1s?nZ4D7r87SzF$hYo#S@bG<}XB)pgzc*W?Y!gw+ipyj<iyS3sfZP-'
        b'>C%e}t+($p$^u>~MvJT8uVkY#7KD#M@5_;abUOg}~w`pc(#?16dXsI)o56nz$nwgw2GjUB8BpL~>Y_EHW{IbG#i!M`_zx&OI=C&;'
        b'gQq^|%zTqUZca&=OPT9PtcaNg9KindVvwkZzPOgQCZ~McAfW<d$b6yNuEcX*~?k$aV?<XemRqx;xhkaKa4v#n-'
        b'^E%vqtoitf=F_K|_a11jKh)gV(A;{Yxo}r=@t)?=y5`D#&Ay!G@T%rmUUPO$b33K@cv<mjTJc~;J|9<Hzpc2DP~1u?F3c$|&MPi0'
        b'D6ZU6?29N4Pb-c^6=!D^w?hsePdI#f!{Nax#jc^w<AutjLn~HwH@@3H>3-e6<bTueT9gtyDSCg0WE-'
        b'q;8r>MDpjCe%&uCdx8*r7Q&uYoT<_9A0JiWCSUeX*<gB`A2lGmcOwZo>T(_41XjsE|2|B*lX|2(qEBmLdI{$FJsDSg=OZ+H5?lWx'
        b's`>Aq!VZqdxlS)kiB-86G~%gofGnaQ(2-{0M-'
        b'(>)|luyUd91={AK93?rVW2)0J>z6(3we?A}ur!NFv#d02uS%!9bXt>6(sWOn)umY@Bb{>6NtzX<SxK5zq^VDug{4_cnq{SFds;e0'
        b'rPHjeAx-zBSzVenrW|fX94-'
        b'VLE(RSgjX7MArXD&^<fBbCWB>ov{{P;ISG;cCWVz@fJ8`}Hi<SQwI~lCn=dTL@000000000000000000000000000000003~FUwo'
        b'K<Oa'
    ),
    0x100002a8000: (
        b'c-rm3F#!M|00g0HX0?y*WCbT+)p~XU0000000000000000002KyZO)ozy'
    ),
    0x100003b0000: (
        b'c-rmIF%19!2m`Qvh~&Y)3T%+jN@xPWQ`02@0000000000000000N{!RGvxro'
    ),
    0x1000048000: (
        b'c-rm3K@9*P3;?lP5QcwOWGeWy?X;$D0000000000000000002M9}oU;07L'
    ),
    0x10000234000: (
        b'c-'
        b'rkdYj9N8dEY&I_n|9Ttu6wsRs!9<daSepNnTlAu>v7L3C2!p$L=%<Rt<47LmW>Ek=q7?J3f20dVmZP!ZtE;%C1(9<PeV))Tsze5Y'
        b';f_&N!J&k{?a*G-'
        b'LCtGyYNc@xyUCPQUM*b5{~hiQP<pbVkdFJ@?#mzW4LoyBmTaK8>Ic$6K>T#<vHe8+N31cF)EgX<+x1(>SJiA*#J@K%l4>pv%)8bp'
        b'IazYIpE@_sa^(R&GNXe#g@ZuOGIAAlP+iyL;~=8_ZSrt{<v!@BNp$r*(RL;Kz};|L_KNfBVO%i{6zwLDe$!kM0hACGYpF;5~X5-'
        b'UWt-zwBag?&Ny~c2_2!5IYF$`u~WXFt3nm<}R3>yJJSFo?Iza_yc_3A=S(ugg$H+pjQ#xja4Mu@~XR9)F=7-'
        b'2t3VTJq|B#G2wS_{_eT!o*ta<2`bc|;?uny{;1F2@n~qDmOb_3Q-'
        b'Rp%CJ)^B9B+LHzyD<&yr$6ttpu;$U&nVnv}rF)=n(xPerNR1tDx_~5!XXji})UkR*My(YhoY!qPQB%X*xmi<JFaQb1SZ1(L=9+{y'
        b'T&|tcRu~u747k$EM_}f0g%U<-G+#M<~Br=Xmuj-$S#$A9Hpazx{ci-'
        b')U`~+LIZX2OJ%p#!;R|t<w+agVzE@J#QIB`rGS@^!I{AdK2vbS|{7DKdA55AM@?kpPJP&4>lC(X1vj{`T8kqE)r|x^}L)}b0?-'
        b'X{ju62{TlP{xi32%sbT&=M>fxH_QyC>#CeXjI&d#Q4D`r0$Qu?|z%1Hb&FndvZHK&Vr7cJTMDF8RyJLvf8?gPO`nfI4;xPw)8Hd~'
        b'{3FoOT`}H=W{Qdm#n~O;WHS4Q`Sie|j-hof6gFN%|)}#3+^ikwqjoh8@&`x(P!?Dx-'
        b'!(}LH=Qj#Fzp=bC>lHY!d>rQ?R>0X;*x9!Nr*}0@wf1;nEsl!WN#t{g{aJRJk=^_LSO1LenzRo%L+=F^-'
        b'1;s99KyOB`#ys}Nm+3Vcp&W!TV3p(pj<nQ3)cN}$hQR`nAG*-NMk&}qp&CDEvZlYQ6G;#@lLP{+&EDk@Ic49khROvBaJX++z-'
        b'W&^wBsUZ@_&qrl)Ys8qx$~qlPfR;sW2EW!f;4v{ovJL{rDQvDRI<GYUCl_T&xFp#(g>FBu`b6J^!Wnq&H88;%kkILg$Z)H;sl41H'
        b'3J=<W+NN*v1>8F5#v8z30FgJGMn`w>f6ADfZh(*%C4!^$z(6o)46gA&GMybD#VrfP?x%9K=fR%wBzh!&^}Yk}fTS^zN^UkQd=S3@'
        b'U!E#wW5V@JtSLNS1FGhWS!t2l2%U6lj~CktNpKdNxvLCd4htfu9=68fT$a4sS#idWa*o*`DSMm9X8fvMGLcG`>DOENtY#n~+PNNn'
        b'9MhfVnRw}&8jQ1|G^jL^te7)6qU;L+bTCWgR@Y06?zlW}iNHD(3G@)5%L^{(G+sg{u%IVEnt2%arf3}YWsYOUk1N=gsoY=CjA)8h'
        b'w>5hgfsgE;gfhmVR3!-'
        b'CJ@nlKB^>;}XRLfh}>BAM_bCF>8>r^}E7$`Hwbpe15?LZG}VlI^!3<`c3|HWLrJ@^if{fV3yPD`bJXL{D~Q0q2w~W;h%tZ3(|d?I'
        b'6AH=Oast7}K7?`H1v)#QfnlE-'
        b'}x5enHrIrWR%#{Wy&S8B1H>!WWD{rWBqqwta43eUKd}uS+8Z=m)}H5%SH&3uoI)<eZ`vdBd0}yec30M_ogjT&Pi)@#qJTax>c>g('
        b'Mf4BY}RzaJGHDgmPfC?yMXs3QXD;lVf`r_Z_cvspyM(wE}L!5qU?CLaLyfBw`~77Gj7giUNe0Nyx*Fpy+s%sFw4`cO#Z8&No3f?1'
        b'gUaDf}ku8il=EKQP9IgmuBeO&+`oK?3}zTKM<P%T89;JNnwYN_2RnxcRgf`bwJ5dSR-qc|?ctWb>#FPi*X3?*(T=SE&~!5ytm9>!'
        b'P4`Fyh(zt`QKLyl8p0UNJ(4$QHk96lwjzBJGIo*_viy7{%{@FeW%y`(Q8H+FTZNvTcmRDQg668|Hg!VA=?r`pAOd;}8An4%<E`EO'
        b'abNwwbt+GxhT{qp^u7eRmk4x;*%J;%J^Np@o5AXQv{1rWf=;r_{D_lRu4F(6v4*BckL1VTmX`^qDPDBV2b-'
        b'#E?*<@}XAY3v+q1hsTShW<c2ca*UMqp<6qW=VHXH9YuH;_HBtBqvUvA_d6m=o=r-tHD=K-'
        b'cHw&DqV|a7&!+g=D%Pu=5nRuNeXLj?u2buyV*MOO+!xh)Q-2|;_*${PmcG%$8xBgkVuCM>-'
        b'kF!%e8geS%uIf4pD)}%dFMK`t>(`Dl-'
        b'${$lDnEu#hp*)7B_>D22m}IM?~C%XbW2zon};grkG@(bz>5GAmvLDlNKnx;0g<42l8^2qCynMsdKJxCq~;#<p}*x?6cCP!m=7wr0'
        b'yH>^8s^{?G%^r!Lm(^`;G)L=l6suHdCaH3Vx2}4amm*u3aIv)HV@cN+D5P=SC)Ju@Nhy2`}p^bPKyAteRZ}Tc5~+C1=LeOgIMxd<'
        b'gsaGVJz`!HxpSuv6u9%*X|*1Ws`41eGajpECpo#3^US)C^Iv0_OpdBb-'
        b'urWVF3l$&87(#wcbz7A%6NLPe`_hyMWXx{u+m`(tr8xwXuOxOWxqf~*zp`eod2NZj=+G1(<`E+!C?MNAsJL3_MJ-AbIREg@&zxP$'
        b'NOAvZ53B_`Ca%DLL={JWfS#XjpqVPB1?2a*nS*oFK#<3P$TWLfMS0Bc|4#$v+bjkmybq<F(HG=yC*rp(&L+<d8WuaQk#T1@$^r9~'
        b'-YrbK?ijzVQSW0)+hWT#(cJDLAM)<WVw?t2>R6Y_r%h0$+DR5f%__k=J*@vj(^uNED+5QnV!fz1D0ze2dWH+TrwFRA9GF-HC4Sl!'
        b'u2)3_>&d^s4^Z2d*#_bTp=$lZM#c5al_@B%=pndeNo{&M-'
        b'w3YzCZiV%&+<Lq!0sBgol!w`yy1XITF3m74oev7PV7QJTbB|mz&pV^OG-h{qx;)s*JbL+y^w}sv))6K|C$H>p((B{j-'
        b'bbQ!Zke0)Qjh=IDRAnWR(;qX7u-'
        b'2n|cx^>KbS<Y#<;H^bR@`B|a7|f4Oj=M@)_1!KU7EC`Iw5_uBcE$WDiR5sjxXD^wrtZ_T}W#?>Yh{8P`!qhbaOGLtc3c@8MhKc?X'
        b'nl!l?|Mu-Wf6P7cn;q?_p*py$^AHem6g9hJ9?fB<z6?u*dl+erMOgl%##Up$@y)P0UJP1y5uzf8AhkRNoTPnjzHH{RKr!k+)l`@O'
        b'OKf;E;gp2mMimn;^IkHS8t0N*1qSeHXW~c7txh_`qS#ER-'
        b'I<{Q6<;wE7uuaEA7AX5*Z*XWLW!)K;9^IyLZBZe(ySv%m4{3$L|*eg4Te4qX~=-'
        b'<h=247q#cjl(>RE63aZrqMC6j^IzU;NE83+q`E8_YUIT!6&zU{Sxl~!T3Epx7lf0wWslKnk0nr#5Uy8&m41)`As=$P@O>BIvGV-'
        b'`vR%ie5#wL>O9|ZwvtSRogDd@YbWYd$M!Zq2#k6EVxNX=(D=#RUqw0KJkBIEao0otC;T+SH2VL`+aC5m<Na)|A8!K6@MP}Ky&Qg3'
        b'xvl~N2ZMXzU9|3>28ET|=arR<GY}w4{|s60kg)VEHDu`-'
        b'w1`{6(lI8OX*c`K$Vec(;si7bOaJwAC+?{Hun!2d&gEGTuQp`gyfTWGC|_uDd(aDUZKV%X(|unkruJeCrd^_&Zu`amL1)+1`m}=j'
        b'Z56c-V-&_(N!eSAv#OVIM8{(;$6~5fmkM!~Jjh<R?Q?_ceKrp!W%e>>om!|-'
        b'^#jIa8GErGz?fX{>{>WA(yn5!djevujLzuUZq%ku!tuI&Nm6w#cf{{vH-'
        b'4+Lg~%bj)a{gv`*l%GFZU>zJ$9>@9%IWr3dQ?N%GbXwD(%+U-'
        b'E_>UDZ63TfJVJQ5F;eg7%we!ycV5SxY>A7_mok$tOdkrpuV@vGT=RN#pvF<MwmlGiLtjV*BpKa0+&KXqGx`5*T1dx%xgXKTF<=JG'
        b'q3f`Yd!N?&%D+%ul3ApJ@Z=6yw)?X^~`tanO(T5UTAqk)C;^>)d@`22`avt^yHcquc#BKLyl0LuxNP7ChU;aM3Lrbj=@F5e8R<y9'
        b'p1M}l{Jn^OzIsBZ0WRG>dY@-'
        b'4au$`Hh_CQf2n0OdWwBL^fR?<Ucxo>S1<|<CpxB$^Z?<+YT8;<way~Sm7XON6d&Mhq{A4q<9poa@YfWK%msQ^LsWSe2(EapJxp^{'
        b'OJ{~@XEZorlf+64>NzJY%yeZroI?qkUoysO>3g@~o;o}y>*VI9S}jmnuLX)5v_OmD38vY^6j;@AR8u0p!?h&@BZ!p>gGe)E4H1jy'
        b'k`#d<%dQMiWESzm${9VIR5ivZBP6B7*(~ZoK=p-dl;%2H<dbxzvC6m>KpFw-'
        b'!Gv1zx|H}G>$VowSx6TgTe&Xct^=r+PvDz~Q>=BZIBU{t_^WY|Wt*=*?AFA|Rd(Z^tdQNf{qHc2mrq$%b;5=7mX%%ch>C{KVHQlY'
        b'zzx~8y`kv22%ZpUy!&H0g-yo;nWT^GDj%7}>>(n;bN_LNKPlO?ua-'
        b'(V%^D#q=Fxv6GQ3A4*@r1N9MW`XqVpUJqx%5O3SZVR*K4pHbFT5e$gOQ+O^)?cBuZrbvWD9{J}qVCnSLFm(IIMVsuw(Z1#x~zvow'
        b'U)A*29NK}9qew#1p%QMadh6Rih*{JWrELhqt8jGO(cjyElzwZc;{GhZbsHVj(e`pSaX{V?uE4PvGAsx9lJPiE%@%avV4v$EjGT`Z'
        b'Uh3l@<r+y5~O_ND8?b)*Y=pQh{HAFMvNyY%}kmMpL%C?X9{eUQbxV=TuwgmPVXbFe>1?|r%Ngf(gY0P2j^gL|qV*7uxM>x~xoM6e'
        b'jIF5%xb{G<N<ZBVeSPPMkOIT~=^@F;gEcRS);oi^s<siRpVgYg`&1OJ|>!!F$uMvdLv9iTTrP-dxmw31^~X|-'
        b'Z~gLW`wcjMj}%_3=<FleFt{yiJxz8A_F%iPY!9N$Zr^|n-2bb6NPYP_5|RdG*^;(JC@`X9tTF6-'
        b'yM30$pDi4m?WyKMO#F}G>lDscwGIA<<MA2VkMqw=kjBfq#KTUMfuJXqPFCfT0sw9&~l_^m4m&!m#XLn!4B)`u>O3PQvBeYj&TA6e'
        b'>;L2YCkpEBTik9!)*8i;3D;1IFVYQoP4deBd32c3=fW6hePRaiGuWsVgrt}?^Vi+8~scqE=hXz5;P&=mw*LO|#T@E)UkTlE?klIN'
        b'!d3OG_Q0|IuWF|B+P^CP`ghgc%ZI15-'
        b'D!jj~iuox51YdvKy)rpDcp(g}+*|Ek8SmJP6V7W@~=rx>FG#_xGZPk%VLG#4(D`XH4pC)L9GvEFhF6j)MBzhL0_G%-'
        b'aN(BPNf&<*ahDQbL!hWJH2GbXCU4+)j%0C-'
        b'vI7jPl|HRLoFui9+old+U&ly&G!G%n6r#uu8JC=U3k2_niItwNRE!jwsz{q|wq#(tBi}f!HNaLS>h;yHx#enQOYamBty+1;{pA}G'
        b'~Oe4@wGF|#nj5|F9g|udqboxm;l@+gSMhYLn851(Jve0LdU65a}20_P+ly`)qynkC=wO!gtF3~Vl(5#T8^CRRVg%mL2k9xeo5Xn?'
        b'@F?0C@MNI+8gfkvGZAHzYO$zF7?>xdCTTsd17HZTE4AT62J9~GNj+=QlJ}aoXy%^&b#`YQ4I!^CKeZIH1YO}H)bK*4FsEO;G`;eM'
        b'@W6G++XYR*&<iMjO!H93P6E;mcH%K$~;y%tpezqX|2XUSyoc693fz#FWgrK>2=PO>6;4K?z3!f3|_Mr|s5a)d}QU?qMP_oeXrlfh'
        b'<3r=jVDj_MOl#o-BlBkfRhbX&|xEGYQ^D~};-AMdzRrh+ai^SeEml~E*d=v3MfcV1&PZ%H$6Z;hXt``eQytTW^ue>5Pab`bx9Ms-'
        b'&t$Nu*7EmK7|HQ1&ccL2Qdatl=>EZF=(?ox9$t!;HII>^0@}jgno^tI;O6l76UVlM*XSxxuc@d=^6!MkPU{FY{x`jJT*aVlJI3f0'
        b'5s^~32x~V5m$eFyfLCVWaa3H-'
        b'**)5EUIB{Xwq7yq~!cs*SehYa>4ENLgZ&4yKnNtn9(n0S@cOhl2JO@dhBgv{#H#&t!_oMyU=zVF_JkH)Cy9tl3_6>7q!Gc7z8Sb~'
        b'FXMKp&CWzWg?Y$nP@)qTz2EmoNU0N`m=BwB<TGXRU3zm{%`VdMg(Dy^hkI*~WPC`O>t5jH-'
        b';73xFFIb=}9gfm5f9RLK(h!sOq~wv<E~%cp=h?Q-_A38lZO_)Zad2XEH`>r+P0wzgk-CUX2n;w=v%myjHu2Tew8QI4e^$h=N^g~?'
        b'vUztP#-vP%hpmCz^U_D0Hk5d+pEXtYZho+$w^YS_)U7=k8)M`2Gzc-?qWB`ExZu!v2wH8LPIN5o_C;Lx60O5re^s0!4Mger%!l-'
        b'TZ(vAN#^S7$PEh(Pw~g828I%2DY|P?iY`nT<%y!Bc1Y?}`Pl?lm@r^BG(f%@qya-'
        b'!HZc*>!UYyO8v6$4mA!T5kvz>Al$Nxo?zO~Hz1LvrMD8~xoRL?%J(|~>GsdF}V^WWRhl##WCtt7$PT6h{`(PREz?^B*$jjEqcRVP'
        b'usR7qVL_*i!~8=<P`JXJ;LF;o@hna@eJW?5z!YeXl}`n{A+&p?`&tD;4rlbkK9q6O7AWJfk)rm`sZv6F&gQQfxY4Sf`SMc5o4_*1'
        b'AQk0R}veBf*J^hDr8d(0q3PGSzVntAJmsCYAa`9x6u0>iE7-'
        b'X7QBJzR63m1Lq*HEH4f?(NIZ<KhAz?*&s_QLgI7t4(?#TJopEH7~gqc#MOLq{DbGzO*<mGn&b{;v&Ap-'
        b'>%%z{`ThH<n2n;Bc$`9ey4kE{xg|@DnFC<I<4S2^ZrbIKWgT(>|*m~CjImISZ0ts&YY~+(T=v8sYO_qapi#NXG?7@83CJ5hW0Q2H'
        b's$E=<xKzdoZTpJ=6rI_oOG4W`sV8#yHA(Vdj*f^9T%cJ&xSoYSjDB|r1WJj9gFM4rIR*w<g&!Exqb(iU5DmfZFfVk>)~&?Jj>I@1'
        b'oewc=dhx_;=`Q|j_Ns$2-l#fc9v)qqS5X1IO-'
        b'7V&b#X_&mVRMtLX0Am0Qm((Un*$c%93$r8Gv%1X<<{lxHNMp3#a*eI&W{d|$<SB^{J)pSv!k&&&O051*GBh~G@lFd5C2^qKEe>KI'
        b'{gCDg+e^hm=QdR8k|Gr5|2!A72sTW6ve+n)`dN`6z}?c40?hcG2Nrs6&8@|xf1u%;s!kAt>U?}&Btb=;{E@s2WZL02BDHz+g3wCP'
        b'$X#-Gb&3}uM9xeWCsqiGrGil^@@Ba0N*q$y#GtzRg3VN`hGmWN4Ou5V(8{DC-uU8l*Mfwp#IXkk^qgfZiSI1xmR-qf6h7`Oj~G%<'
        b'DV@TBkWeHhtppNmcU#%MG(zb|8PFS~sH@MJA|yK_ESN#CeVF;D*Fgy>Xaq<lwmyzNNFsiLd*&el#|+pwd3ydbkY#+OtFWw2}IJK9'
        b'D{cU1P3yZ0`X$`P0&FVHEaKagmcwr}d^Mx)v*={=I)AV!@~5nMBi;H?+5Rln^LHt;@bcvMxYDV`|>QR7j)D`Gol8`StzTyzNH4px'
        b'b$<sG<6>jI-9w@X>2_y}Dkg$A>!;f#6)a#eH|VqfLX6EzrHKP1V{W~iE7S~$#|W|8?B*1nimX2re-YTW*FL1mTU%#*nO=O}xQHCf'
        b'a4DsN|HmH+aB%B4xnAQ+E|%d51?(kc(yB=#VAtk19mwXg&2dghJ})VOGml`#>uyIoso6Tj)nMVy!D`3U9X*4CWiymU=<<L8<F;d*'
        b'c)_v^*ffia3~-'
        b'B?*eVEkhJ*haP>^ND#fqdGo=vVOOCIzFk@yr`mD<i?^=P1xOBk{Oh>3wG{;`^gPEHp@yf$K(v#@cCt{;HjgSjRxmw)H==h;E9T=l'
        b'1m$QZ2So59O_pqI4v$KqS`F}+3YlH3Kl^p+QWaA(s|41@^5$Od^B?9<U8^NH5g`N4GYpMSk_<a=0$dMNNL*Of<MJAdrj29mtS<f;'
        b'!--X@tP-5ere;5a-j!$Z{)lWrZ%<+9=JJmk?N0)Y*M>-'
        b'qljiG<;+Xt)g|(N*(H$AxHA_i>O|EOAfioU6AhBaP;Id{rPWA@8aEaz{V7kew!@2m9y42)t>;0MmYJ^Ol&@^f^&G~K3e0h~Q-'
        b'c+holWuq2r|>!cB4KWq)JLv;KyWT@AW!^tQ_Y%6;00hyc+4>F?}t35bJjP@tFI544puFTb#PbsUBKBk18SBec@X7Y_LS0>b@bLjh'
        b'F%C{I3ztF>!kCr!%on`wL3$fwj-tXYKR<^z+~8{tfQ'
    ),
    0x10000240000: (
        b'c-pmEU1%HG6~4MwJj%p~S;e*-'
        b't=BslTTWKa8f|0})eb^2avIu~gwm4k_Q$wyOCJ*G%eF6yVr|T_P?w}&)3kLgfp;ClF6%%x1QOGR5ZX{unn0H3!Gt`75SBdnA%#$S'
        b'N1C5=XYQHNSkpk5<c>J!eBb%bxp!vH#?MJxf8LIEkbKwt=SNAI{cofq(Tuu8a~%@NXX|vf+(FdH$ho1jhs$I<LoO%s6*5Lhj!5PF'
        b'>6*N8YeG7*OO^)9okXI93=kT>`P~}>P1`@Yq;&r3Go|yFe^iD`pDV-'
        b'BzbeNLcSe7`m)TjWs3b!7#iH-C|E1J(`u`3qB(;}ZNfA=a?k9hmCh_x?==e@jp~uNCQX`#}@$534J-b2(``0Rsl8UsioL-'
        b'XXI*}^*Y>jT5zZOwbqhyJeXH^#Gl?z%`?iqp6{pLoz8QoVG(jCL>j(WC6rOK)7Wtmn|J-aRppOr|tcVzeO9SlbN=E!y9_g_Rils-'
        b'CNyv44BmjBjd?29tFZt+qcj7T&;T}%As)(VN9dWWs6Nm<89$k(I#uRdnKQrNw3-XS%4x-'
        b'(5yBGIqezY{7QBJ#rEC?!dml7{E0j||UjJptCWb!$EMk}_n*`g<qs^#}HPL0Pod?}FbK!S8Q_b!Csa-'
        b'Z!z)X|1nxlGSwNicHA&vU^CaA|<r5b-G@bQu;L=>ml{xlBPT<{;<$djQ{Kx#dsl`vpw8FJlwWD?9)9^)5D<dp;D(g-'
        b'2=O(l^!zW@W5HR<Fb_DENO-%tzl`>wq*WoScI(HLt?(`@|5B{B@9mq-'
        b'P4#J^D@H9eZ<2(2k(}Ln&Dv`c)05Dz*)NQvLths=sMt+WiX>?JS&z}73gjg(a|FW&x3$jwxVz`_89T-'
        b'C@^Ch!r0@0jA>5B8Zl3QV8{FnR3pUl6v46?SYI;;mZyQMYsSXn;{F8^@3YXjf6*@YT<mA;91M1`*v$@F1WJC5D0vIP`Z92CFeSf2'
        b'JZy!==BrSYOwQOW$~KFI6DF3_Lhiqm^op>&-md-{ShA+2QduL>ro|Yu7~2m2q8#XWtbG;4JtB8nI9tpCvMcG9l5(INJn`?pgK-'
        b'cyP_3?VA)YQ9Pw-uqV=NBp$l)O=hoRb$xQlxh>-'
        b'W{Sy%?MF>c4}E%?gJ_L9oPaEVjn<2vCg~5xB4@BHn=|5${u|S`$dTiimr_nCP@1jyDmQ`(>VcS01!~+VQI(4<|u>QUDiJc`xkQK;'
        b'_*C4~c+z(@z;wLZ-WsI_ehn1rMe<4^B(TU`%U1D(?fm8Di;0u=EDjCWfUqaJ|fUsJst}w=W>~mKRsNeeH5D?8*H|Pfj6tQtj~1G1'
        b'iaNLn?4zz%tw)xG(srbpYwf0|=J>z#7A_3<T!gORXvr??7nWtL^TGT<oy#?nnCW5Yl%w1gqN4e#x<^A+@3fu6=Ar)<W;Q!${v9La'
        b'+>N<1F@jA(kN#@1AF2!;+BuVI<z+ZJdS0@eT(*3oqO8qJ1}m^xgdkp8bLOU$*gZjAf8|*dOpLte+CZjAdN0dS}?OgsSxb(svIaST'
        b'ccghG97nn0L)Xt)oc12Lji`3=;2XVBOES)#_62kKQyqtj%jQM%0+Rkkikz#xw0r`X3wP5rFaN5A5|ZkVEixckm$6x3dUWqwVCD%S'
        b'INdwd{6t?#f2il~=#FyMjvKSUHHqd@x|m;jD}yydT`gv$B|#G11w;GlMfoN6lWh<IW>GI)vaEbLA#LmN~`_Avrk|+8%VMojucv`8'
        b'0SZHjeE7c?3(|r7!>Q6k;s-?bfe_qxc;Tht*Z4ftPVR-ookK#`<AT?gq;eW!Dto@S(jM@wStgZA3$cZ5f=79-'
        b'^n+qkpjRO#*!CzwGq_T>mlGeT94+5%F=&lm8lsx$fix=AZzy<nWnnHwVi|4hkOmZ8ZnWd=8rLjluWJBH$9@Eh2aeBD~i;E58Qt8f'
        b'Pjo-eTMNvuq1<IEi2?hLA%H(_{!a)ZBH{@B?e*7{CT=rG#Lf^vGkYwK9X$N(rgYQV9KO2I09BLch{{YUMcK65>6E;5`;XKf-'
        b'i%EIiE$b9fxVbUZvgyD%MZySE5yg~OP8&;HJ*ze_ew_l3RYepGs)5xIFk22TGczA>K;E;XJGBK*@qftXKnYZvwV8^n3ve7Y#jYb5'
        b'6SVirmbPJ{ei1lVlf7rlLl)AJ_uH|Vi&&koI#@JHg@kqHyul7Vkwa8AhmrBJy?&Q6}(A}2}%e+HZ^AM)7E+?Jl1`b03+Tf&Id6A{'
        b';w>kGE<Yp>6n#j5y?kvaFZwxv;-'
        b'Y)X#jZq<CgUi((RUv}QNzeSssD~itl>t5B$<%yiIj)13cMV?xI|5+6>3aX~%FML(^8>KVi8aZuZD!mfv2VmRsV9_tf%Lulh`OwdC'
        b'RsOjy2PO`>yyAbo?c7*iz2a~A-E<Y*gWmX^sput*c9H3w4n-'
        b'GlfW4y2y%!bDiYUzq@7r9=8uz!8OTYzS|5G3K=R_V`{wf$2`!imZv9_SIzUg?s2QXgr!8q^1s{fb5YDoRmSt0&iYoU$YXrXm2&2J'
        b'yzI~P!U-'
        b'AC<9;p7D<;WHm4)IB_AIFIgkM>GEqB?#1hRag7QPE_q*`e0mZLp4uA+7GzXLyKy^+D7jSwnr1j05#N3TH6Oie^*HK{dY-CR%at*J'
        b't|cibNuI5nsf7sa#f$3zfsi|Cw5OrnWQ;84`%!o8o&90Sw)kJ<`lg?gMaEveTsfOxofd8MIRg4@#dZZh4Hn^e7pST<`jMDx9l3D<'
        b'$pA%=x<fXVuoCnjVbyLiRM*(ivC)2ie5IR=qXvSr|7TI#^gNR+>s{xXmr7xqR-'
        b'4(Q}nv$w0W9m>j|(<*R6GHie6uT<D|X*z+Nw$zF@E41;1Cp?{9;3>m;0sSyS|EeI-UdNfYy2{P$1xM*sck-e@}76S+!Q9-'
        b'oV*?wI8}z_O(jX8E>ld7p0C>&<&)sLXrdEZuR$*ug!YoHIHsyQbBiNPWY$B>uj_V!nsOeAf|klzS4KHR^<2)5W(UV>&CV2rKsy5B'
        b'D5cc5u%jRilHjYnr?jVI5={df+VGcUbD=Sozpsg<aF+r;&P@o$WGy)0-'
        b'^rO%OL^>=A<JfrBxL%kp_6%k26t!!rb;a5456@$krjQ{osqZ!pHLx`(T}jxq>ik6o5z&JtY*vDSel@fT|r^D|I|5X(~p%chI16vt'
        b'K~2e6Fk5qyYXc^Z&+%aV}$7f8I%LgW5LyWESX=UL}8r{@(oJ<l+`MwGmTV0{@lH<*%NAs)6uWAjxgO17rw8H=*bqJ6R$pR=atomg'
        b'IPSAYEU{A_ucM2iiJigB{gEs`Moi*jI1&pYC_rsrGF0kSJu)AOz8;JJVQwWjACs<o!)op`!zJT2w{*~hKvd4Y$d9ENJG>3NPZ>+~'
        b'#UY|5+uTGR86{%cLoJF&!VEOw1s=U|b>o{MJnm?cHTJFq0;eF{};0*O}<aSs@CbH9qjn+VMPYOB-pEPfT_;UvgU3gCh&?}a@ZsJt'
        b'8DArUZd`YB^d$aFVSN8O^n;K4NK!D%TOjOmPz%KJcXhFE$LEWLrXiDBstTrVGbsJst}w=W>~mKRsNeeH5D?8*H|Pfj6tQtj~1G1i'
        b'aNLn?4zz%tw)xG(sr)tsJJ{s+;UnIZ'
    ),
    0x10000244000: (
        b'c-'
        b'rk*L2DaF6dtd^QiKtzN)dKjM_sFmn7T%_gyY6x*%;TD_L5Ktlt3`_rjv8bsUpZ!lpfsTKuUEGSm2`eP_QACfXS^tp!m>RjzJWka%'
        b'iD6)vjlE-e~8|?n-+IWIhmvS$OY#-}m0k?3!e)YAs7#(DvejK~fomEaXV`G&kq1r$2aSh7{QPl{ES0{nXF%gnU-KOco!c^5)mQe6'
        b'5+9cm94z-kqv9yJn8spIFm&_U@Oq7-'
        b'?a~&%h#Ogh&R9WH^yZPNc>~Brlp!ZxN|?f!BK^)O*P4JqGojsOl~9dXI#9StR2a)Z23+4S2oq=hlAf4zIleYA+u1^%7XOZ}D{#;a'
        b'ZIC&46<i)Es6g$TFA#4Z_qMAZnTcU&7R+qMB~aJ3z%US4H4bLb#M<{r72g4)4E#{ZPuKB-'
        b'0&4lIi{s?c_32Z&{|jlSQGuyxy`*dk`t8eV^A0>lV6|g1TY1RuDdw*!uT5A3-'
        b'sS%tJ*s`wGSAu*c+z(Lk+ghy6%sw=Qv21TISm7aH3$jLTAN-KnBmmyvpxV$VbasdqVc-'
        b'#3EY8tB~HZ?g=YebY#jVw$#V`5~7y<6`{7IbH`GZ+y<z>%ha@4}5(E*|)2RR?CxkE4WcbX01A|=K(jW0bi*Q$z+jCH_`*Kd;Ew{l'
        b'@+Asm6$V!t5QdFUx~Rt;HuPRcLSw^4P-~H{>JNGL;7eH;ZqNI6T@Xeu~o#A)x^%A)k)4wzvkV0yyk1j`M-'
        b'v6Sqt=6SSMp#*2bM*pNIXiz{B5Fc0iVEyk2YfO}2hjsoi2TWeoq$0}apkX(YxjV6l-NVzD#ec65f`c5nR1`E3Ax#XtDE1=qh2c3-'
        b'I;*JXM<R_cEUYVM8d0X?ulFOB3ZOzJ@&@xW5}8`Xop=z*Jq+~>S(pe5vMBYZ6x-^a?yKLmW)ol4Hvp4dM>w$#H7gp-'
        b'|shZv`g1U#g{Idb#BS=j>I;H+#SoHrCcMxB)gGAo<Nd~PPNUo{Y&Hxt;eXvnN=11%xnErjn@0{aoxS6j*TtklD8gwu9%{T$%5J@M'
        b'WmofUy&?IWL~bGt9F+r9OkcOJF=DwB-uKF{&zr#Juf-VQqM+rgChc3=_jO|Em`Jby|?pL=f?t^G1dyL{JkGdw@%OU9nT9pK;hfE&'
        b'+!pw4}jB(dkM=M}NXygOXngzw9}BkLZ&F5}l;+?Vq2B&t1fcT#GL+$b4;3T~EXB6rW**7IS1syOx{am40{$mePFh6`g~ArZeU?#a'
        b'IxJ@F>zg=u8Sv((6YchP&l?wmW%o1@RGb8vF8>cYMxv+7(gZ`P!91Tvk=G98hK-'
        b'#_=Hisl26!oGj@MMW?A@Sc1|c0Eq5zh(UcxV=!Q80K*w;TG2q=N`8wzSsHnH_K#JRsX+Zd*f$S)gRFt8titT%NyT$9o;pJS+a9!q'
        b'@(R8;H;Ppo<+7d5v{hTh47qf(PGcX@e*hO)c-a_{kAM)#K~wRrhY>;8J$Ot>d!{L?*WbnAsqJ=s)p?|H1dQ*^e4uy^=JZbXkxn-'
        b'4Lb+KoeOk(PdW{pUpE<FKqveZ(h0p+qT8vm+fSTse|ib+_Fp|!5str1u!js1IuC@~L&R=BVZ6psG|Cyx|JzB1kqqWC@f3J#>cqy+'
        b'0om_AGJQ^-->uxqUM4SpfBDrZTW9IxqdQGBG&D3cG&D3cG&D3cG&D3cG&D3cG&D3cG&D3cG&Ejs{0|XyQI7'
    ),
    0x1000058000: (
        b'c-'
        b'rmIy9ok86a~<`i?|4)fvLd;28L#~BUWNyEe2L$36>yMU<bNCFfmu;9Jm8B@4aD|BFVXGmfY^i<xy|SJfB7O+v_4<w)=rMG>R0HT*'
        b'mMH^3)#o`Sf?mdfHcetF|L4Q;w2(U3E!jL$dE`shh5<O?yX~V>f#k)<ZLzQ2+n{000000000000000_){+%#u=a'
    ),
}


def build_mixed_partial_context_pages():
    """Return fresh complete pages for the fixed mixed partial program."""
    pages = {}
    for dva, encoded in _MIXED_PARTIAL_CONTEXT_PAGES_B85.items():
        page = zlib.decompress(base64.b85decode(encoded))
        if (
            len(page) != PAGE_SIZE
            or hashlib.sha256(page).hexdigest()
            != MIXED_PARTIAL_CONTEXT_PAGE_SHA256[dva]
        ):
            raise ValueError("G17G mixed-partial caller asset changed")
        pages[dva] = page
    return pages
