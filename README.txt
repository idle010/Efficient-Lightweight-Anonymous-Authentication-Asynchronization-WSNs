Synopsis
This project contains the implementation details of the proposed scheme in "An Efficient Lightweight Authentication Scheme with Adaptive Resilience of Asynchronization Attacks for Wireless Sensor Networks".

Environmental requirements
Programs can run under Windows, Linux, and Macs. 
Install Proverif 1.96, download Address: http://proverif.inria.fr/
No additional libraries are required. 
ProVerif is a command-line tool which can be executed using the syntax:
           ./proverif [options] filename

Code example£¬"ours-IEEE.pv" is the filename

D:\>D:\proverif1.96\proverif.exe D:\proverif1.96\ours-IEEE.pv
Linear part:
Completing equations...
Completed equations:
Convergent part:
XOR(XOR(x_13,y_14),y_14) = x_13
Completing equations...
Completed equations:
XOR(XOR(x_13,y_14),y_14) = x_13
Process:
{1}new IDi: bitstring;
{2}new PWi: bitstring;
{3}new bi: bitstring;
{4}new Snj: bitstring;
{5}let Fi: bitstring = XOR(Ki,H3(IDi,PWi,bi)) in
{6}let V: bitstring = H1(Mod(Concat(Ki,H3(IDi,PWi,bi)),CVaule)) in
(
    {7}!
    {8}let xKi: bitstring = XOR(Fi,H3(IDi,PWi,bi)) in
    {9}if (xKi = Ki) then
    {10}let V': bitstring = H1(Mod(Concat(xKi,H3(IDi,PWi,bi)),CVaule)) in
    {11}if (V' = V) then
    {12}event beginGUparam(GWN);
    {13}new rA: nonce;
    {14}new T_57: timestamp;
    {15}let CTT1: bitstring = XOR(Concat(rA,Snj),H3(IDi,xKi,Kug)) in
    {16}let vv1: bitstring = H7(IDi,Snj,PID,rA,xKi,Kug,T_57) in
    {17}out(c1, (PID,CTT1,vv1,T_57,isFresh(T_57,true)));
    {18}in(c1, (CT3: bitstring,v4: bitstring));
    {19}let (xsk: bitstring,xPID0: bitstring) = XOR(CT3,H4(rA,PID,xKi,Kug)) in
    {20}let v'4: bitstring = H5(Snj,IDi,xsk,rA,xPID0) in
    {21}if (v'4 = v4) then
    {22}event endUGparam(user);
    {23}out(c1, encrypt(secretA,xsk))
) | (
    {24}!
    {25}in(c1, (gPID: bitstring,CT1: bitstring,v1: bitstring,T': timestamp,checkT: bool));
    {26}if (checkT = true) then
    {27}if (gPID = PID) then
    {28}let (rAg: bitstring,gSN: bitstring) = XOR(CT1,H3(IDi,Ki,Kug)) in
    {29}event beginUGparam(user);
    {30}let v'1: bitstring = H7(IDi,gSN,gPID,rAg,Ki,Kug,T') in
    {31}if ((v'1 = v1) && (gSN = Snj)) then
    {32}new sk: bitstring;
    {33}event beginSGparam(SN);
    {34}let CTT2: bitstring = XOR(Concat(sk,IDi),H3(Kgs,gSN,NSj)) in
    {35}let vv2: bitstring = H5(IDi,Snj,sk,Kgs,NSj) in
    {36}out(c2, (CTT2,vv2));
    {37}in(c2, v3: bitstring);
    {38}let v'3: bitstring = H4(Snj,IDi,sk,Kgs) in
    {39}if (v'3 = v3) then
    {40}event endGSparam(GWN);
    {41}out(c2, encrypt(secretC,sk));
    {42}new PID0: bitstring;
    {43}let CTT3: bitstring = XOR(Concat(sk,PID0),H4(rAg,PID,Ki,Kug)) in
    {44}let vv4: bitstring = H5(Snj,IDi,sk,rAg,PID0) in
    {45}out(c1, (CTT3,vv4));
    {46}event endGUparam(GWN);
    {47}out(c1, encrypt(secretB,sk))
) | (
    {48}!
    {49}in(c2, (CT2: bitstring,v2: bitstring));
    {50}event beginGSparam(GWN);
    {51}let (skx: bitstring,xA2: bitstring) = XOR(CT2,H3(Kgs,Snj,NSj)) in
    {52}let v'2: bitstring = H5(xA2,Snj,skx,Kgs,NSj) in
    {53}if (v'2 = v2) then
    {54}out(c2, H4(Snj,xA2,skx,Kgs));
    {55}event endSGparam(SN);
    {56}out(c2, encrypt(secretD,skx))
)

-- Query not attacker(secretA[]); not attacker(secretB[]); not attacker(secretC[]); not attacker(secretD[])
Completing...
Starting query not attacker(secretA[])
RESULT not attacker(secretA[]) is true.
Starting query not attacker(secretB[])
RESULT not attacker(secretB[]) is true.
Starting query not attacker(secretC[])
RESULT not attacker(secretC[]) is true.
Starting query not attacker(secretD[])
RESULT not attacker(secretD[]) is true.
-- Query inj-event(endSGparam(x_1485)) ==> inj-event(beginSGparam(x_1485))
Completing...
Starting query inj-event(endSGparam(x_1485)) ==> inj-event(beginSGparam(x_1485))
RESULT inj-event(endSGparam(x_1485)) ==> inj-event(beginSGparam(x_1485)) is true.
-- Query inj-event(endGSparam(x_2913)) ==> inj-event(beginGSparam(x_2913))
Completing...
Starting query inj-event(endGSparam(x_2913)) ==> inj-event(beginGSparam(x_2913))
RESULT inj-event(endGSparam(x_2913)) ==> inj-event(beginGSparam(x_2913)) is true.
-- Query inj-event(endGUparam(x_4306)) ==> inj-event(beginGUparam(x_4306))
Completing...
Starting query inj-event(endGUparam(x_4306)) ==> inj-event(beginGUparam(x_4306))
RESULT inj-event(endGUparam(x_4306)) ==> inj-event(beginGUparam(x_4306)) is true.
-- Query inj-event(endUGparam(x_5704)) ==> inj-event(beginUGparam(x_5704))
Completing...
Starting query inj-event(endUGparam(x_5704)) ==> inj-event(beginUGparam(x_5704))
RESULT inj-event(endUGparam(x_5704)) ==> inj-event(beginUGparam(x_5704)) is true.


