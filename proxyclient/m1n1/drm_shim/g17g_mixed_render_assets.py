# SPDX-License-Identifier: GPL-2.0-only
"""Caller-owned compiler assets for the earliest coherent mixed clear.

These two pages are bounded Metal compiler/resource products from the
canonical earliest render-plus-compute witness.  They contain no firmware,
kernel, page-table, or accelerator lifecycle state.  Runtime code expands
and hash-checks these local assets without consulting a capture artifact.
"""

import base64
import hashlib
import zlib

PAGE_SIZE = 0x4000
BASE_MANIFEST_SHA256 = 'c1a3c35054bf743540ace0b51d16e5c698049af0d6c2d600ca1cebedd1c51c6f'
SOURCE_MANIFEST_SHA256 = '04bc8a5adc8bbeb5c08011fd3fe716a2861bb3a7a317fcf80d283a29a1c47f9b'
MIXED_RENDER_CONTEXT_PAGE_SHA256 = {
    0x10000000000: 'b3f401d29ba6d12ddee1045df5670b20614971b22e41996770afb6267d8a6579',
    0x10000018000: '3350bd87f4d0a00444e16f8c0cbd6a034ff0bd5d6e5f6469e7bf1d7e8067f667',
}
MIXED_RENDER_CONTEXT_PAGE_BASE_SHA256 = {
    0x10000000000: 'a31aaa0f07737fa94ed91ebd4a445abb96e4475c8772bd87e2c5487f7a8a6118',
    0x10000018000: 'cb6d460eab398bcaeaddd46f78231f46c052b6a43e081eb79398a514441ad819',
}

_MIXED_RENDER_CONTEXT_PAGES_B85 = {
    0x10000000000: (
        b'c-rk-eQ;FQbwBU!llJK$R;wq3q$fbTZ?)Rh3JI~2&`P+HkWB2@)2WRo9YZ=sAtnYl)EJuvNHW}AeIS8}gs2<Kj_q'
        b'BooJEkBuX@%ZQ($PC#!hDHF!{qUX-Yl$Bbj8TuA4s$lQBK#zWox?!?VaUo=yuR-'
        b'n(Dtp3mPo_dd~MgGK!*{9pd}321TTO7cX{+PQ7Gquo<|$M_xXo~k>>?`Zdw-'
        b'7$VgyQg$c+YZhW03XQUf;ZIp?f;km^Zk2yap40Vu(MuQlsWD(mR3Zag(YBPm4>rtjf_v`yu1N8QmY49H;}TdXi%c'
        b'qm{jQOam?GlNBVsEFa9@Yp--0edWfrjUJLD#ta~BOT;WpivGltHYrrOxY@pPjw7^jD3d#)%zHLxQ-UhI%b&+XS&F'
        b'X7Cik;Pkr`1+&Q+-R`Q~}zYEl|s&tgQf_5LMe$eD*}OHV-'
        b'~8M|H=&DqxZNb1V`=Yr~S$1!oxQu(FYKg>iw=k$IPS9jqv}!xE^MODdrNz$<ImA7$8*&HWeiXR-djSov3@|5PIlU'
        b'qRMa&_iU2LX&(2(C_ihN=~kP&i;?_s}=`g(6tJc(e>!f6r+EI{f~jmjWJ-'
        b'j`HZd<v*rh6TX7{De*@$aeCt=im5@Ef4?22k1JJOnfxp2R2rA8KO#XV*`Gv27>nrUbAHWFH`~w(aAT*^#BQ7{3+t'
        b'kM$<DP#-J-y%PbajJ#-'
        b'3>9#kDehh+?!hZ4%vw<Tz89FCq&CuS_EZU5j?T&hGQ$P{&=<1Me+D{vD4^cHymp~uBwL^13@V%$(6X4MJZs|as1~'
        b'z{@eze7E+zJC9=V7<YBq%A-'
        b'FA~`F1yx&%0s9*jKR3m59g}>S0RnK`%}q7buCoqo5QLvK+6689j8!egCGh?MDq>0Io;^ptFg`G-brq3ZO>3-'
        b'0bfi^B$o$9ylEFj*B-*Kk6N0BRCrVpsJ~&0Mw)2BM}8hZ00^`Y4s!C5*EgJJR!kEfS=Zo@)GY-ZYuztdn4=^(ZHS'
        b'0;h64+!`wSgV@T!wfGegoL+^NM7T58uE^Jo}j(t2_iWKlUY@?pvtt_h2StB1-'
        b'N*D_#8Qf|@Ym5xLS|#w<?9l9rYnLy@CA)-'
        b'g?DD1m*6QK4esE~4;N2zgg2C;NtdRWrYqr<w_;SXLPk=ePq%Wtup@rF5=)<^i<&f%W;FwDppuhAxx*mBhH6zJo9q'
        b'rV~fuv4w`DL?3Rzq2+6%?Sy4nkj7)^>jZefPOkNVRI9FXUI#mQ0er@pvF=m*5hUpChZjef05KM69o(^*ZUjU6uQ='
        b'KS1wE4i^j_3;JIGv|l^Gg*qM!C@+u>d=WT+W1S}s(-'
        b'`XK0FD_WhiR;x!xkFzkJ6YAV2fBcYK{qSG)%d$HHodD*+Q9L5}qnr<n#5o`^cD!W@6HzR@9MNcK}<4BF5C@#+ji`'
        b'J0xuKX6y~Pme8D_Z`To{L`E-5FhMsE75x**^7`RAJGdO}Oi&3Z-ytebx9mD9=C`rr#`w@`J7~!-'
        b'd4?NlrtaM}CdOKCCB2EECOa7I-}ViAXzYov_Bbv&H)rjJdrdKlkn^mNb-'
        b'JdQETew#?Ie?Fyeb_*=WT_y&KpxY_Syj7PU71HdSKnSokcXC<kFiU8sIWTk1rzD8MF>*RFa-dt$CzE1$Qw9;TBJ='
        b'twCF1-$_G;6cyvLov0*Dee32*HL~5DZ?vao^(bO5K|gMQ;)axkjFe483rC7@#3tV)t-'
        b'2IpJHcOE=eQ<m>YMe85u8^=wz^>#+F#<0x*g@9E!`e992nm|qh$MQ2KI1Im#xPUn0j&o<8W&Ggdw6lIK6$^h|sA1'
        b'{q4MPs)DhJ-s!!yY?}Ji6UH(b%Aj9bMe*hQX37eIahh9$bG4D}eAuW!eNH&Nk;3T`7V+xJ_Q-'
        b'H8$vttRO)He_N~CU+|Jz2PtwM=t7@JBc8t=S(3FQ#kJG!J4+9UGILJu+{J=mZMku9*Bn;tHQa9%*n<8miSYtF+OD'
        b'pb$oMt@N))lid-FclyTwcDT)*Bj>giD@q{<jC##L~UcFFoHa4`kN?$3#E0VmsS#us8S1Cnzly@Ymjpf=75er=Tk<'
        b'mzHg|62ig>_1f=HFj9rmJhSUt2Ay8i-Pe)V`XrICNK8*grz5-'
        b'dqYEvp!0W|O5AQI#LI!SawrnM7+Kl`L`d^v+t?F@PmV+}t9kk{b`<dyrvByS9TmTbMHX_w%ZMLIk?tF%PHt8mIjS'
        b'+9d4`G!jL81{0n4I=c^Y+xjwdX;?-kHX*A6Wd=kxDC<#Bj3uEyuk*)uPp-'
        b'd5#1onL|leXFvtG7>+Gr;xcx7;4_?Hv0aO95mdfyFt89b+D8_7v&)8DThB$tgDy#hSufLPB%&^8_eg~^8L2Z1D+;'
        b'7F_jbbqV6Q5j$Y4c1G;4QL;zoGV;b;gD?{-'
        b'{zmpFmUBqmQNf5tAt+8VVt|9^h}Xaa$q+j54S~5r2zNOW|(92+EYq37B>8G%%$;h?v9TzS5y(z>*-'
        b'=s5@Y$%pLb(h6n)By7uC_s<6S7s^iaAVBQdO6qqdQs^-'
        b'RI*=h%{nezK8K$$EHl_wayjH}e$5@sY;52sZBP?QjE0{ze!;m&4^sO#j>C-'
        b'{3{z{ywJ+$I|Ia&OoO58)f*ZPIZ0A*>o1H1axbXGRz!>_Q_+0d9&(-K1dV5-^aXPX8Q9*~)HPctrtJ4R{-QW`*A-'
        b'BA20-'
        b';LXl6HpJ2(t_}J{y@nWvGYUmid=YE6kt3MXn3xgpL(zb@fdlG@)*5GQzSJ2i8YzX_SmA{n&Ku?#$;}F!5Ah%9hl{'
        b'Y`By@4}xb{<<4J#EmfU5(z8X%I|nNc-'
        b'>J0Hc&jdYqFa06><xev@Yl>BAH2=*Xywt2u?&jEG3#pK~2o<&`%6KADQbWxQ3-'
        b'!Ufq4(j!Bu{Wc=U&p!4qL*R@D+gKyCT~Q0E6ISprVN<Xt{6gY)W9A?==Vop9|<*MWiv*jCO+(6vrBQZciQRS{Xcw'
        b'u4JbEbds{f1ciJPNGc@<3)Amb427~OHJ!`gh57#o_uKH8YcMunF)g1Bk;3~1hq@aRYO5xDeH|*yJm$S>Wo<`j1in'
        b'pd^Xa$3+#PjHP^|8HfF*im3T*SV_!=tLR=-Bi+($;|{9@j&W9%xbR9O>&<#wI-7-'
        b'r;4)gEM7etS4vOL_1YqvK{cdnbvYpknfk9P_wkYD7LqRQ?+y*dj!R8D}Av+M8~SqMg?f?f%M#+H64v<+B=|XX~>4'
        b'28ZlcF1MYBLl(A?uVfq2?b}k~R4R~U7jy&X&SRc%kEJcbtm(suc@k}vVN^eM!JV@UyO|0y85348v6jgULOqNyE7f'
        b'GS=)Q;K?=nbd$*k94%Gq|9x3F`1g*k2M_8f5k*wBz5gfqvDwX)HaT;={nmKVw6lp2iufx$0rqsraSMWuem1<^D1K'
        b'NRA8?^K7>ij7SfsWhj6?ik1WB$WFHUh(b0>ai1`CfmoB(fDh8zGQci$@%PA?)9Eu~4*5Zj{~G&s;<%M8cL4d+ML+'
        b'GU(fnd3#fQoNbF4@jfFkLj$P$$<$`Yccd+dA~Q^Q8Y&Io5OKD$4Sr-'
        b'T2O@ibxLsbPtyYwyI<q=~19YDq}lF%gQQH6IeVfe3ej5N-q!&S&~(r@+%SoUET(i-^ata+!;vOkE-'
        b'{R7#zuk(1PlAYv#-'
        b'x+!!^@8SQB1l@9<>Jr#VNNB#bXYdwz7pn;K1SSe3+$_*N7e$j9ltpxhkcq_+6N_obON6}wPq$|AmYH}<w8`hPczd'
        b'E4qGonSx>rqP6?nQk9u#=`fyv!Xfuyr%pYIk(x?X7Ls+obb<O7$6>X-'
        b'|AQnOnC@$$oX;L4cMez1GU&j_tInX_lxh?0kJSnM%#`uTR`5MZ0Rb~d)xC$J39@$mp5*0l~=VYEGv9A3pZ*RTDsb'
        b'v-CwjP1polcu`^K5FZ3A9f+`toYy+`^@liRF-zGx~6`(68n~=P+s%Hq)#BCI9<n8q8|rD-'
        b'w)#xSH_Aw``4lrQ|8QT)r7l~?oipaQ?1nkaWACT+>EtV2^~zBkz_FYyMzGa_G8nn(0e?MK|T|C1tuFzI-'
        b'HAjGvz5xCQO`}Rs6@_@pi1CeazUJsj4g=6$qZipm$bwG$vVk-#yjcHG_z@o2wB0meS1L4E`ZcM~EjvAFb4gNDt-i'
        b'PMn!2HCfWpuwU^X8ASxm;&|_|G@XeTGZgt;3C?lpWNvOqWKbUI9m~?1)ch|dSq6<$s7PqJg3yvsQNt+BU~kf-'
        b'V`4ArFRFhWp;Jo`>?hL_1v9*!u}y*fa5`gXrD@zhW5fEGH-'
        b'8w@<sq7zrGxSCINgXvF#_TW<=&V&IMhxj5r}EK!#D>mM<*PNIh=#%GxQLmLzs_qm^mlT#9B6p{o;;I_Yb*2obf5<'
        b'2i;V^9l-e4Pec$Q(iIg(aT@sv^}F`8IQj*`GpR8`IOq!NHXE-C+wr`Or_82{+tS}*UKbVmcx`t?=&Dmm;Z-'
        b'&lB?aP}bse6;E)XXtkP}27JtX2jt!F=^<_cW6HsGz`r1|RsVU4YFpJrkdp0lshETV{*qxsEVaX)CTMU2#_Dl{<?d'
        b'0~hoEQKUz;!Gfk$fk&|5=B+f=~fApnb_Vk4ijPDTf?iFi~DnHn)C|c4XKC>N(bA90t`HgsQ8fXWLYXYm`UA?*$&_'
        b'SHP^mNF+1rCl_63{oKDj(1zgd<Bfwtq&0w9^&t0Z9&HeTte=;F(h?%=itXUHqs>5u_#5%Scu2y%~4`ap1SCI_Bu2'
        b'pwbq`X=^W4l%zk}zwEN=hLgzziHU9zku?>Xgx7u$1iav6+|GS3E7%zw%^USYwl!X|H;5M?>sLYqc}Tvp@o4oNBb|'
        b'W<J_k_LT~>2%h+-w2=|IEumX6n$s@qG!>*=PZc)Z-'
        b'O&5h?_%B$ke29F9XI@=?u<@%z|Y(VB%g`gSXs<A*1aBH&XjA%*H&YdK~-'
        b')5eeC$U3a%q8Q`He1x6K}RyRS)95#XE)hNvFu8^7fhmHl<(ET|lIqb)+-'
        b'b}nzBw%{ox!*1zn%vU;$90`l3_`vAsb;Bv-E(%2ze_IoFiAtn8Rf%Y#5^<+1k=cs-szoJ|u>e*gT)yIlnV>T0Y{s'
        b'}_NG*7RsuJ@YiZuo9v5jsTX~yJ$S0V%#5u*AJ37w>HBaQ1AA!t1>)=zu@trwwKp3+E`ly{<~jiuX<VWeU`^Sc3WI'
        b'R|6O#<5y%r`&MMM5m$}%3tl`yc9D+gYUs=xG61jled|7iquyJFDLe{H)|xc$2mhpckk@pwoKg=H|wSV-ySpHG``m'
        b'}+(H#pFK=@X`|-`I8M`vIlt59mD&5{T@+o6PaYL_?uC;=`XO4-'
        b'R@Mh#~OCwp03B;;2qA|k>y&VTj%{%kaMv5xrmS%O1j7l(CzN{3K-r5HQO0m_iK)-'
        b'nx4fb~*R$d7Hm#oOLM0Dxi#jM8?q7@H{DoprEymMqwq8+b`{zDStOJ7qc_vF|aJ>tfirZ3<!Pljf1FnXBIlYLDl7'
        b'9GU#EdHzq`#7Ql))t8Rsj4C_+YciWVMUUyTQ<ku!rE%n>ree`_&(Odd+K9vwTX&i3sxRM!i31Nr~Y{`#QG_tV4p#'
        b'KX`14MAWn8WU~|JR#Dl4tZ#+EQiTKbpx|Z5AZ9AnsrQg^%xDNAk+rEbVYj&0=BJ$&bD522)HT%|LYag}{CEhvp<X'
        b'fO@>UbtL)C%mK(@&m7S(%s{+zorEznM;1Vt(ft!6n7w8Joz0oNf)i-'
        b'0<{wlM%sPK=?YLwlQ*qG7{nl&KbA;e(lp02@W5n{6bh{DnN7aq;Me}sqK_O#r&z{Q>8;8ab_T`b?zW*-Kr-qz%@n'
        b'jSQ2G8kY1PIX4QPmw&$$5Zg#`hV&Qd6!OCEdskNK&XS=V(zjAgq{#+O0+jVoF+4iqHvb!iSy8dhKa5Gct<7YeYj3'
        b'd@!ujje@Z*KS&)}W(nY5r{czV3I{f2+f+&5#me%jnvD9SM_v1J83HUqu`UoH!aKOx}a<o&Fc17}wN4(>XHWY(@$8'
        b';Hf1@?;>OJSm4CKFVK@HZYVzA9(WG|aP`#QZZj6&{l~o><{QRh(u_rn&$H?H+}l3Xc?d8j*A8_Yf<P@rWC=!GHue'
        b'a2FqQ%j7Mb+|#T7;0riN$6M9j7B`LkzA+`J$&I&xToNbOT*yfq2Sf%r0Few{f$H^s_f^IJ{2k|z%}#F^=|+!qY9%'
        b'APUvx#6Js?0rT&mA<WJ`~GgTy)lV#)`;E{eZdWCi^oR4djUXSlzx4%H0SP<em>=n^KRddw=VAfvxZJU#p5&P38n#'
        b'0%#^8HY<37WPqRU~$(0%gYQvZ#I|EqRg+%q&LiPUcxO(~0di#A#RJ$j0d&wLZANbL#)Hm4gISZdZ;Vk_6tIoRnXP'
        b'kBNKRLh9UPu`rCcd6Z%%{j(=$oi(KzuE70#<jYbby{_zreynn5By#!YDH0P#EcKo??Uaoe<yXyG+FH<KC#9od<Ed'
        b'#4aC7n%_hiAEdkRQ^$=VwY(vhyKnv|rRa0Vy|y|WafPu4jXaL^D~ssmOO8_};>#P#$_m8YLBnin{%P6ftYqUocsg'
        b'`q-hJ29*l7;48NG0iWM`rNxOU|d`V-'
        b'd2G0jz>lAHi<Q(YVy##v4ryG9wazt9T_Nq(DZO&6;L^(9Xeg9_FB3Vm^7`ql#bwVZw<bHnjc%ZCglOZBgPG~55nY'
        b'=4(?GTZ;tocTRD^M9Pv?@a&3ky^R_a$%-FQ3xl!(kT_-q2?-'
        b'xN9>vro@VE{U8kp4DTnEvsNwve=S%6kn6BoQ><&M%*x|?79elI{OYh*J9U{}Lg?7NF*I7=#aWZFzIh1}fk5XU`B_'
        b'l=25R`hel+r(fVy;$xZo%_U=k27=*-'
        b'1<7q|r{T#PgJeR^GGN;pcbgJ+nhRwZr+G9sc2t9p+GaZyqIe4kdOzN55#nfYX?(l?+u^j^Ev|@T2!F<oRWuR?cuS'
        b'Ph-Eb*x~)WHD*|7>{oee%(zoyg6IA(XL<f@PBiAq@*4|TZshG>+bm@HP2SP9Ei21B-T%RY-'
        b'`{>_y8pvsbw7vqXR|i&6eI6x1ntT3<Ud(>@*gc^{V;FaSb6ft7CZd$Gt=hBpNS{Kvso>wSuJ)wl9ok(spS&}%NLU'
        b'6PxtD7LYC$<rTe)-zX(MX6{M)#i~bj~0m+let2ul(&~M7BdD*}sD-op%H7^@{@ag#Lapdrw<F(}F3(8ZRl_&o!J4'
        b'a)VoH)8;hYIzx@Y)8)Jl!L&54&parm>B8!(WdxtCcyjI4xvxWM#?v7;#|fV<`^i$>Ll{?>Uqf()&hBZ`CaLbuOg)'
        b'9E~khEiBBhmbdPw=IVZ)9gJUO`FG{m;n5uX=s9xbdinBP%+B%hWfpqS^0XUO85<YW^fHS$TDA}_+(pxKcDR#LMSh'
        b'w#KE=x`bFevAmgN?*EYI6Ftz=oAcf4%7i<ehg@LQRu?lZg0<F|6Lx?d2JS6E=OZXu7p82!)D*b0ky(DTLxD+{m48'
        b'y7y!TUS|N@+u2iR^;ttR<f+hTkm)CR+k08t3ET`yB3=d=kT73yM7DYt+l{i!$MZqV)Er2Z5kG_V&onBRvFp&%yGB'
        b'Q0(WaIWU0M}TI|IIWvN|A?{}?*Q<N6eeVqlrb@xyUFU)UU-nH;lmS0QU4Orl=-$EXL-uj=)$}>k}0gHI>=UEF=m9'
        b'VhJ0`qviyM;59EWLHL1@5l4kR_0}&8%cuowweNyLfAp1;4BFj)`p+{5Iw7_uJ-s>pai>%k=*(`oXxt6mTi(OD$B-'
        b'rp~k%+0Cqs_vOgA;jwIgYmN<bZg)LF3*2tD&{fl7Y&*vq%@(oNe6Kd2XN~50cKx*5-'
        b'320Hj#h#eJO}fPIcu%7TIfA^4`=0twbHs!ZE#l$ZnHqt=GiRYAqziRXCY7PJlo`9<vAK#XJM0dpIHuCx0sxn;dyu'
        b'ZPV9dGkm|P('
    ),
    0x10000018000: (
        b'c-rmLF-RM67{=l6y<BUMU_-'
        b'e<G}c3;gc3@IP^1WE$RIRO2M3`J4h|h092`1Glc9q{2Zs(F92`27>d?WVLx&6wZY~{)6clmj&>=&IKvO^8J8+XmN'
        b'Q)ibC;43hm%GdVzNBjXss8)pm!1vW-'
        b'1Xhhedj|T*Du%{w@(me1}(Z3nKhq!!<}c&SeFm<x;|_0P1BuE=TTvLS#AR!8?xJMkmcAA%d@*IV#92N71%u%vk7*'
        b'e71;w;Vh>rFRoEjo#UA5YxA2ei>7~_Ue~2t{$fJN56PQF1C6rOY6sA!{4YR0Y4)a*RB9^d>=UBlDtm7q`c!dqT#w'
        b'On2Ew-'
        b'?YcX*Foe8e6;;WJv;#{s_JD~|9DCpg1*{6HH&(Lom$gh4jQ1^s@1_nABH4NkDt=BrznOg}L`mP|GM9oWgK!3W%v8'
        b'=l_u&;rX^&hi#pCoTu+M|lv>HRH#Jzunu(Ig<1HD0jxJ$W~d~?A-'
        b't2|F7B4`ZHawqF|9tTE%KMZ_BpEZ&<QvtJ|Wj*g6*+q$@V-'
        b'TuwW}a60kp&3hGV>CCU1c+b`SG7%9G5fKp)5fKp)5fKp)5fKp)5fKp)5fKp)5t0AK1;~zut^'
    ),
}

_MIXED_RENDER_CONTEXT_PAGE_XOR_B85 = {
    0x10000000000: (
        b'c-rk)eQ;A(cE7rMev%*Z%j5Y=eilN0k}O%4jj#k5TPP1_jfvSf0oD!1#2CCRkc5PkO&c~%B0oM1l<;A%jW7g+t+l'
        b'aDAlMFxP4O~rho+gflV-BamUdeLX_xM%+ste-WiuV7_rCk|Wy^o;?!P(=Bl#Ncx#xGz`Q6_=0HiH#X-iw$(w4Tgr'
        b'7dk~OIzB~mbSE|Ep2H_TiVi=wzQ=!ZD~te+R~P`w52U=X-nH5Xq*4I|3076f`FlCs16(iG$@lb&}|ujOSBpg@bp1'
        b'Bm;s74W&6bT#X-8t4F>suO#5iC1ZaYR-9KS&{nVuMYpxvZm3zR!8V4|EJC5hqmYUinhbBY+#ydBtA6|TA<BRW@i@'
        b'!6(6;prBty)G?KPmzj_^@mN8tBkd&FCk=vJd~Xi~~Xu7!d%FJWg<~6|fyLRh0>3xEjm@{eYIM(3$qP4+4O`4MPgZ'
        b'y6*?YKD(F=Gv!LpPvEVNtD0iL2?pT7{l(~<?{?V^7;?*k0PRi#BcRw1U%$c90RI{9vT7|sA?)e6(w`rBdFchc6TY'
        b'8s?b009!Qr0$^Q$v-7kpWP()X_TG(k|3dALIaz3}jw!#WYl=yQ9PhN^+r+RLwv!28^?{dvBX;0dQrSor;Z?*0lEj'
        b'&Haq9po*h5&0rG1==5GY9c~G$Gb}bcWV>%&koSfw9<C4T|<3X0{VFiv;ih$Er%eVfxrv^J5{@vB{@Rte8Rdo7F+j'
        b'zWj>ov6<=g%L)Yc}SC4BXrzXslom=*ARxkjb*93sZkZF8}LKs7*#ucjg*bW>{D|nv)?AN=WWbITguz}%8uMIY4LU'
        b'n(xAiBS?`X&u@>iQrJhV7aW27r1`0qB=?yx1Ord;VP~;7_|g7eu76$la3~16qk~X_MH1#~VNCEg0J=(Sz+~26&w9'
        b'9NG+mtb;CfilE&UhI_qcP&nGp4ZuN|-R?e3YrAB->v3>kT`0`mmKw9Pb;o{?eV=;sikRu2$LOp<gVFytG$??84cA'
        b'@g9Qds8f3I<LAe2czy)fVRgVJ$o*%SGja`%TfP~14b|7K8}e|P(HRZUyi^98MMo3$$qJNHOA=cR9RNd5izp?CU#t'
        b'gV~}&cfB~``jc;>hIX;vmep&ii(R+0CFZcXlF!V6m;^Rf=PHk<GpMcI>L9!9p~V+2!CwfvIBv}zwFEFt9v$}ZDBX'
        b'<di3gn06}H6Ytfn9XDHy<cL5g28v+Z3!lOd&ysqN*EaUY%W!X786EL$=cC#MGG9p}|p0sG7clyJ;qRt5CtzRYd$r'
        b'1j@iQI{ElE&k-NLvE?+8%4#^4d!a;J;iQ1k{ESFv1l6tpU}#9hg5XXX%_uw|(h|FbEp{%LBln?KwJGtNoy|TxdVB'
        b'A85FRp^lgOTsmh>qeUx$;Hu>SXELCz?|I{u8g|Hal_m8z(c`^~v#Af2eFfQxn)PITadVIN=j!@rXq_)q)&pEuUiD'
        b'`*S^o&K777km!x3sqDhw0=E2<->aO&3LATV0wNoY5Za4Q<ZE>4sheTA?8<A%06gWprelKNY8I&>R?rz#4;4OwS8d'
        b'-8^1EQssxvS9us8}!%oiR?Y8`E-U9d40>Ta{`{d0aB^R!)I5C2OfKPw*gfu@$fPB@K>A;dB9b(NH}quRy?dg9uDk'
        b'}T+EX%aiaX23O{#Ewyu-I<9C1iv*iU_kAAyl8`|kce5a2pwdkxU%PqUM>jNLZX&7<gUdaw|&u8%V;DA^b)a95)Pr'
        b'2<J>bjcYNh@8`xLi}iDrjdn0o*fFQgdGQT@|grkD-+_#jTH`)qDQVl2|MiwC`63EZ1L?8h_|*V&C|@&UCi(hRKUj'
        b'kuNjmud{&{qtYie7Z6k^f{Kd!r!#ODxvfep(>Rt*Z7pmd@ME?9n9$yTEd-HZ2Je?6rmPd@91+!@om*%;esMs|50k'
        b'3--8Lz5h9Au#EHTvUpSH>U+|^)#ARg7`*e5-3VSQNK$Tu~<(_Ux#i_gC>s5?Qt)A>sSu6zsG31_iTgU+jE0(EWok'
        b'4{vaJQ{&G-{{=;92^e^q$!beKgxYM3s<Sc`p)dR?T_W)k=gN9GfP-z@ptWp44A>-j&kUye$`_jJce@frji?ob8~k'
        b'38-tP?X?WCno8(4nL%FfIqSs|m@1|mR=jptH2u23+g;V^wT?QP^iT7C8Bs$x<V@xi1bN7Te7Otx^wSQsy@B4K)`z'
        b'GvRTteBu6Zep0&RLf<m+~iW=C4{?L9C7ft!wkDAF6fq0J34V>ymonKd&ZaKcSL;lT^vW-!tGCF<RgdLhH}~uT=7<'
        b'Bo?1EIcYsx)96eUi}4TDB{-J5>ze?%L%tIf0UPpusW<u=3KZy3JX`@FEPnx3KlrZ442$Ff9@m)HB^nQhBK*r112{'
        b'E3=&1;QQTO&fggwf^>w6m6BfGoYI8KGvb|PLA2v1FM*?HApDu@}EFf<!B5X1)Q`d&XmQOEBXy#YB0^ceP@6TEP6n'
        b'({2EXly+4#9ep!=b(934qjQCSIW@n=GKQ+7+`G2Dd~6d96U<Mf%HuSxj|7Se;cjjK-MF3-7dromN6FH$Y0SQtG9?'
        b'XfqcqNn}_X&+>L8l+-p`j>xkyq0B<{zA>a-@0}QMW-^gP9Q@M|=Vw+H`7LPZITBrBn>KJMQ?>dGVBLWxc%fA+-K?'
        b'{Gcr7@88OMT1VZ8LPcyezr%k%yxL{CI+g@dOV~A`dt(gVDS^#Cf@(=4A}$<q*kBKFQ0oI4_t3@J^BFPFbti<(Y&P'
        b'F`E>^JE-N>SQdgI!G@6P*Aq7BU6*GjnuGb#p6h<?pCq9bXl=%5{hxvs7e}kR${R<ka{&5CEXoON_yk+Y36xko(Hi'
        b'@oUJ*QvPEgY87Z9Hbi<J}XQ~2!sM#N{IHq|a5d}ew(ff*M*gP2jhPviXiTKPhie>?PxgB+K{zxSkCU*QWB>Og8H|'
        b'LznK{~nsnzvqz`-GiC@t030vHrnJd<1GH|Y^qJgzsJ|1^FEl#zw^ph&fwn;gM)*N!oQauWyJZn4f?guQb~Cb{|V)'
        b'x)PVBPS!7AbLvwRH521uScm_xw?$!Upg4~)|)lNxkSw#u6`j8E^YXL(zfM`kV0VzNu1v1h41PvmP8hOtSKX(;?2Y'
        b'p6fgI*6OVZVMp`m5`_%Ab7ZebKh{?px(WV2#2wd!kH(c47^Rhv-fSO)7>aZHv{PmcnR0hO*y0y;(sMGmKi%ro!C~'
        b'xHpiFssF`-?3!3_#JuDfLOy}SG0Tey<xKUmFYX0yR%#4;$x86zBWV3%K_Nja$qR>KF_Bo7CwVF9byGN&#R*=H*OO'
        b'ROFNR&@#){sFlU`3vE$+-&EKkS329tgfOtGqbznQ@DiP-b#y!;&4Gbyo`ld;F2h1rPZ5hpijz#33=lISWfyT@w5u'
        b'PDUsMw%^YZeq!+hN+;9LyV3=>KgPXS9uOn8H}nj602PBtKB(Oo@FL)875RhmGJYKTt#C{HT+quYj;#F06w*Alel3'
        b'c(mKwXTHI@UG0#<mqPY=lv;|cF$&JAK%^3f%C{(?$HWe@I@GnTs3&?{`^)QPU=v2IbYb+%%Y*KivHjx)v+UAuPwL'
        b'UzG-ht>}O&DzubF+h+2O<sUc&l5gRnanHPEgML(tpI!qD%7TGenUE0y!iW2E`Is0Bj@{!`lfbcnqCDmw;A07E;M$'
        b'#+jTP?Uz}c+=61+L3T>X$-*p7-l}kNUP|o29M~f-x*c<1&-`B4x6Z~sB`2F>ocv`{wdO=QS<%Fsqnfx#wmUPJm?l'
        b'0#H1QfsZU_u0DsQGHp7erv|0ii;KNZuVaZS9k(kIwu&Nx#Ozt#FvajdoO*;JYsdnif8FoEA&6W>g&iAzOQkC`F+o'
        b'*}A<arTKG>o6fb#?8>gIQx8M3`O;IC#Yye5;XB>R1>3E=s9AkN~L!-96h%f4uVfovZW2(Aue)<sO+x3yHHOU;ys~'
        b'__r&z(?kHQ%!k(JrymTt;6V99JJ@QE+_UaTN@73B>$-L{ryt~??o5{PyG2XrO=w}I)>`uwM6(yFGysMvscXucnX9'
        b'n*os0lVtO5UA(;e(XD&&<*LI}|-uo9aF6_N3^27wY})l)e9ay!Q)8@8`6%F#$*GYlL_C<wlzy@vaf`uCL*ofOxlC'
        b'Maz|vcYP(cRJ^;>RG6A~pI2h(PKbqy#j-S&PC;+`?v%XyqJn#OGVjJ`5goQ!yemrGsPmjDwXk^(E&O8qynB<dM?K'
        b'-2)e~3?uWL$;{Y&V)7s*a4@8%@UB6zi0D>3h0!`1p?QneN*YGFqfnTd`!c#6>*lYwCLglJeqTlyCDhRhH=RY@jJX'
        b'M@if)agwx?al|*dS!ZZCRmeAILx!W$LfQG!(6EEg)`CDYmc=8qMebxankHi{rY&HRSXHSK7-ZKllLC?Tgk~?ocot'
        b'ufuU`NZ+1%T*A~Dk(_Q(p5E|A9_$H|4a@l>W!iSbvetn!^&~|jWI3MlgB^ZbpgQdz&j}ADZ7!<w`*w9u-`CDtF)3'
        b'x41#SlDKMPkL;G8U^}ja5XkMrUE@MPBNniDvWAF}`+?7x_i<B0oW1<d!`0A_wS2-Yu*|>Te}Dlf*txuVN=uR2&!;'
        b'&k&QZpkgJcKrcbXV@2#!tf;>23M$<N5}UKWiCr-2GvPY(2D4<%r2$?P@_|bVyDwKXogp*t`n+7z5|&KrnI5VF4vY'
        b'FB!3^pHgIra#V?%Byu0ztXIve-Vwo@?=oo2<uSTGA_Ug}dk3?mO8*rdm!y+6oJsyj`D+~qd4_s63<WlAib1gb1=P'
        b'&KguYvOOMcioqL&1VQAU!F5*R<q`L^*y`(yoQ~qyiV!}{<g<jsnk(ug&)Qcn_Ah_V_mAQ`(SKpf~UKsKJ`wmfULz'
        b'Zd%D|Eu{hyQP3UaPhBnk8@#${wAwQ`OWxCs`PIplqvc=h;U#*T*)7=j7D&da!boZX(L8-sQ>2A<Z$LcSGOm_j9?k'
        b'*+MUC*9eWxD$cp6-?<?38r>-}#<8-Ti-Vb-M!'
    ),
    0x10000018000: (
        b'c-rmMPe_w-7zgn0_uV^Pv22+Ku~jo9j7C_D7$s=sL1>2vi9iDn5*~Ii@Zdq_><<W82uVnJkPwmz5)6_G93*5HJt}'
        b'D^<-vo{BnhSU`}J&HI)w93ba_7P`|cgTy}Wy#-}4So|5K7%uUjkW%6`#Wd0Fd$E1zn!M@O!8iRLQ>z)m^$ONt}`N'
        b'wK6vQYtBv1SJO~A;}@hVM(Rri6ksJCaID{Bqt?N$tnK(`crxC@!k0NH4$L2d(k{H^Jdlwd#e~Z6ZKZ}Eb16TjF-^'
        b'Bi)dmTExd|2ThS@!N%o<K{pjOe3^0iyzQPE5G0OWG=L5O(DyC>K$8T8RG?qDsRZe1E&NGa9T<3(x@8tdcKyzc^R{'
        b'K}8+uAPK!Bkq_EnGR|9NeGX)f8k$vGfVFh1O=9k!y$x2R`@_aLaw0;p4>&a)=+ze9^4gYragsH}BTonh8_Kmu9T&'
        b'0vpONv*}1PTduV-zShC(Ccz|cvWLCwV?PHtDAx~jgwHt27aZpsrZ~wdS)1brE^vv<T;VFyT;~QegyT9sCs%)R%lX'
        b'aIAJ2+Z5ll9sf)V@L9<>kcZKM%KHDYK&Jk==$JGqL14VOOp8DI%ZrQ#4PDD@W2nDdD!Giwv(w5j)wC7zq7=CL^!l'
        b'zO{cdCzHM|K|?eDCjb`q~bf-ioFA#!5u@phW8+ZjZoFEGNkFU7d3Wq=7+WE>>kMexOSf`h9s4eHc1*VcDwUiyNyR'
        b'Y&-`rNzf87&C_x1xs6zu<(EfY>kf(o@3{##LMp?~T*0G*3%DhnKh0;IDys(Y!>|o~~CnoRwZ|Z-zQc5YMlu}A5rI'
        b'b=iDW#NBN-3q3Qc5YMlu}A5rIb=iDW%lk^b^vc-;n'
    ),
}


def build_mixed_render_context_pages(compute_publication_count=2):
    """Return hash-gated compiler pages for one/two-publication mixed work."""
    compute_publication_count = int(compute_publication_count)
    if compute_publication_count not in (1, 2):
        raise ValueError(
            "G17G mixed compiler variant requires one or two publications"
        )
    pages = {}
    for dva, encoded in _MIXED_RENDER_CONTEXT_PAGES_B85.items():
        page = zlib.decompress(base64.b85decode(encoded))
        if compute_publication_count == 2:
            delta = zlib.decompress(base64.b85decode(
                _MIXED_RENDER_CONTEXT_PAGE_XOR_B85[dva]
            ))
            if len(delta) != PAGE_SIZE:
                raise ValueError("G17G mixed-render caller delta changed")
            page = bytes(value ^ patch for value, patch in zip(page, delta))
        expected = (
            MIXED_RENDER_CONTEXT_PAGE_SHA256
            if compute_publication_count == 2 else
            MIXED_RENDER_CONTEXT_PAGE_BASE_SHA256
        )[dva]
        if (
            len(page) != PAGE_SIZE
            or hashlib.sha256(page).hexdigest() != expected
        ):
            raise ValueError("G17G mixed-render caller asset changed")
        pages[dva] = page
    return pages
