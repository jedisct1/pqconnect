## <a name="cooperative">Cooperative security</a>

PQConnect is not in competition with existing application-specific cryptographic layers,
such as TLS and SSH.
PQConnect adds an _extra_ cryptographic layer
as an application-independent "bump in the wire"
in the network stack.
Deploying PQConnect means that the attacker
has to break PQConnect _and_ has to break
whatever cryptographic mechanisms the application provides.
This layering has an important effect on security decisions,
as explained below.

## <a name="non-nocere">Primum non nocere</a>

Modifying cryptography often damages security.
This damage can easily outweigh whatever advantages the modification was intended to have.
For example, upgrading from ECC to SIKE was claimed to
[solidly protect against quantum computers](https://eprint.iacr.org/2021/543),
but SIKE was shown
[11 years after its introduction](https://eprint.iacr.org/2022/975)
to be efficiently breakable.
There are many other examples of broken post-quantum proposals;
out of 69 round-1 submissions to the NIST Post-Quantum Cryptography Standardization Project,
[48% are now known to not reach their security goals](https://cr.yp.to/papers.html#qrcsp),
including 25% of the submissions that were not broken at the end of round 1
and 36% of the submissions that were selected by NIST for round 2.
As another example,
OCB2, which was claimed to be an improvement over OCB1,
was shown
[15 years after its introduction](https://eprint.iacr.org/2019/311)
to be efficiently breakable.

However,
for an _extra_ layer of security,
the risk analysis is different.
A collapse of the extra layer of security
simply reverts to the previous situation, the situation without that layer.

We are not saying that it doesn't matter whether PQConnect is secure.
We have tried hard to make sure that PQConnect is secure by itself,
protecting applications that make unencrypted connections
or that use broken encryption.
We are continuing efforts to to improve the level of assurance of PQConnect,
and we encourage further analysis.

What we _are_ saying is that,
beyond being designed for security benefits,
PQConnect is designed to minimize security risks.

Beyond the basic structure of PQConnect as a new security mechanism,
the rest of this page describes
some PQConnect software features
aimed at making sure that PQConnect will not damage existing security
even if something goes horribly wrong.
There is a
[separate page](crypto.html)
regarding PQConnect's cryptographic goals.

## <a name="virtual">Virtualization</a>

System administrators often run hypervisors such as Xen
to isolate applications inside virtual machines.
The PQConnect software supports
[client-in-a-bottle](sysadmin.html#client-in-a-bottle)
and
[server-in-a-bottle](sysadmin.html#server-in-a-bottle)
modes.
In these modes,
the PQConnect software runs inside a virtual machine
while protecting connections to and from the entire system.
The overall data flow of network traffic
is similar to what would happen if PQConnect handling were delegated to an external router,
but the router is within the same machine,
limiting opportunities for attackers to intercept unencrypted traffic.

Beware that virtual machines are not perfect isolation.
For example,
various Xen
[security holes](https://xenbits.xen.org/xsa/) have been discovered,
and [timing attacks](https://timing.attacks.cr.yp.to)
have sometimes been demonstrated reading data from other virtual machines.

## <a name="memory">Memory safety</a>

The PQConnect software is written in Python
with careful use of libraries.
Using high-level languages such as Python
limits the level of assurance of constant-time data handling and key erasure,
but these are not memory-safety risks.

Cryptographic operations are carried out via libraries
that follow the SUPERCOP/NaCl API,
rather than libraries whose APIs inherently require dynamic memory allocation.
The relevant library code has been systematically tested under memory checkers such as valgrind.
Memory checkers do not necessarily exercise all code paths,
but all data flow from attacker-controlled inputs to branches or memory addresses
is avoided in the specific [public-key cryptosystems](crypto.html) used in PQConnect.

## <a name="file">File safety</a>

The PQConnect software is primarily memory-based.
The filesystem is used in a few limited ways
(e.g., storing the server's long-term keys),
with no data flow from attacker-controlled inputs.

## <a name="port">Port security</a>

Malicious users on a multi-user machine,
or attackers compromising applications,
can bind to specific TCP ports or UDP ports,
preventing PQConnect from using those ports.
However,
the operating system prevents non-root users from binding to ports below 1024,
so you can simply choose ports below 1024 for running PQConnect.
For example, you are probably not using
port 584 ("keyserver") or port 624 ("cryptoadmin")
for anything else;
you can
[use those](sysadmin.html#ports)
for a PQConnect server.

## <a name="privsep">Privilege separation</a>

Privileges are used at run time
by the PQConnect software components
that hook into the networking stack
and that create and read/write packets on the TUN network interface.
The PQConnect software employs privilege separation
to isolate code that requires these privileges from the rest of the software.
Most of the code is run in a process as a non-root `pqconnect` user.
Untrusted data arriving on the network is piped from the root process to the non-root process for handling.

## <a name="limit">Privilege limitation</a>

When the PQConnect software is run under systemd (as currently recommended),
various external constraints are applied to the system calls used by the software,
although this is generally less limiting than running in a virtual machine.
