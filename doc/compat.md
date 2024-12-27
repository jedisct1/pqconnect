## <a name="backward">Backward compatibility</a>

Preserving connectivity is critical.
After you install the PQConnect client software,
your machine will connect to PQConnect servers
_and_ will continue to connect to non-PQConnect servers.
PQConnect is designed so that the PQConnect client software
detects PQConnect servers _without_ sending extra queries to non-PQConnect servers.
(Such queries might trigger hyperactive firewalls to break connectivity.)
Similarly,
if you are a sysadmin installing the PQConnect server software,
your machine will continue to allow connections from non-PQConnect clients.

This compatibility works using CNAME records, a standard DNS feature
(for example, `www.amazon.com` relies on CNAME records).
To announce PQConnect support for `www.your.server`,
you will rename the existing DNS records for `www.your.server`
(typically just an A record showing the server's IP address)
under a new name determined by PQConnect,
and you will set up a DNS CNAME record
pointing from `www.your.server` to the new name.
For example,
`www.pqconnect.net` has a CNAME record pointing to
`pq1u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1.pqconnect.net`,
which in turn has an A record listing the server's IP address.
Non-PQConnect clients follow the CNAME record
and connect to the server.
PQConnect clients recognize the CNAME record as a PQConnect announcement
and make an encrypted connection to the server.

## <a name="forward">Forward compatibility</a>

PQConnect announcements include a version number `pq1`.
This supports smooth future upgrades
in which clients are upgraded to allow a modified `pq2` protocol,
and then servers can freely begin announcing `pq2`.

## <a name="subdomain">Subdomains</a>

PQConnect is not limited to `www.your.server`.
You can also announce PQConnect support
for `imap.your.server`, `zulip.your.server`, or whatever other subdomains you want
within your DNS domains.

However,
you cannot set up a DNS CNAME record
specifically for the second-level name `your.server`
delegated from the top-level `.server` administrators.
DNS does not allow CNAME records to have exactly the same name as other records,
such as delegation records.
It would be possible for PQConnect to work around this restriction
by inserting PQConnect announcements into delegation records,
but currently PQConnect focuses on protecting subdomains.

## Operating systems <a name="operating-system">

The initial PQConnect software release is for Linux.
The software installation
relies on packages supplied by Linux distributions.
Package names are not synchronized across Linux distributions.
The installation currently understands the names for
Debian; Debian derivatives such as Ubuntu and Raspbian; Arch; and Gentoo.
Adding further distributions should be easy.

Support for non-Linux operating systems is planned,
handling the different mechanisms
that different operating systems provide
for reading and writing IP-layer packets.
The PQConnect system as a whole
is designed to be compatible with any operating system.
The PQConnect software is written in Python.
The underlying C libraries for cryptography have already been ported to MacOS.

Accessing the IP layer is not the only way to implement the PQConnect protocol.
Existing user-level applications access the kernel's network stack
via system calls, normally via `libc`.
It is possible to modify those network packets by modifying the kernel,
by modifying `libc`,
or by pre-loading a PQConnect dynamic library,
still without touching the individual applications.
Also, most applications
access DNS at the servers designated in `/etc/resolv.conf`,
usually via `libc`,
so it is possible to modify DNS packets by changing `libc`,
by modifying `/etc/resolv.conf`
to point to local DNS software that handles PQConnect,
or by modifying existing local DNS software to handle PQConnect
(via plugins where applicable, or by code modifications).
These software choices can also be of interest to apply PQConnect to
applications that manage to dodge the current PQConnect software.

## <a name="application">Applications</a>

Our experiments have found the PQConnect software
successfully wrapping post-quantum cryptography around a wide range of applications.
However,
there is no guarantee that PQConnect covers all applications.
For example,
an application might read a server address from a local file
without using DNS queries,
might use its own encrypted tunnel to a DNS proxy,
or might otherwise
deviate from the normal modular usage of DNS services
provided by the operating system.
These applications do not receive the benefits of PQConnect:
they will continue to make non-PQConnect-protected connections as usual.

A notable example is Firefox,
which automatically uses DNS over HTTPS in some cases
to send DNS queries to Cloudflare.
A DNS proxy (or DNS packet rewriting) can disable this by creating an IP address for `use-application-dns.net`;
this allows Firefox to benefit from PQConnect,
and is still compatible with passing DNS queries locally to a modular DNS-over-HTTPS client.
A user _manually_ configuring Firefox to use DNS over HTTPS will prevent Firefox from using PQConnect.

## <a name="tls">Transport-layer security</a>

SSH connections, TLS connections, etc. work smoothly over PQConnect.
The software managing those security mechanisms
doesn't notice that everything is protected inside a PQConnect tunnel.
The PQConnect software doesn't notice that the packets it's encrypting
already have another layer of encryption.

## <a name="vpn">VPNs</a>

Conceptually,
running the PQConnect protocol
on top of a VPN protocol,
or vice versa,
is a simple matter of routing packets
in the desired order through PQConnect and the VPN.
So far we haven't written scripts to do this,
but if you have specific use cases then please share details in the
Compatibility channel on the [PQConnect chat server](index.html#chat).

## <a name="firewall">Firewalls</a>

PQConnect encrypts and authenticates complete IP packets,
including port numbers.
After decrypting a packet,
PQConnect forwards the packet to the local machine
on whichever port number is specified by the client.
One consequence of this encryption
is that you cannot rely on a firewall outside your machine to block ports:
any desired port blocking must be handled by a firewall inside your machine.
Note that an external firewall also does not block
attackers who have compromised a router or network card
between the firewall and your computer.

You may be behind a firewall that restricts which ports you can use:
for example, the firewall may block low ports, or may block high ports.
PQConnect is flexible in which ports it uses.
The `-p` option for the `pqconnect` program chooses a client port.
The `-p` and `-k` options for the `pqconnect-server` program choose a crypto-server port and a key-server port.
All of these are UDP ports.

## <a name="ip-versions">IP versions</a>

Our PQConnect tests have been with IPv4,
but the protocol should also work with IPv6.
The PQConnect handshake packets are small enough
that even multiple levels of surrounding tunnels
should stay below the 1500-byte Ethernet limit on packet sizes.

## <a name="surveillance">Application-layer surveillance</a>

The PQConnect server software
automatically replaces client IP addresses with local addresses such as 10.10.0.5
when it delivers packets to applications running on your server.
Hiding client addresses can help protect privacy
against applications that are careless in handling client data,
and can help comply with privacy regulations.

If you need applications to be able to check client locations
to route clients to nearby servers for efficiency,
one option is to provide different DNS responses
to clients in different locations
(using, e.g., the "client location" feature in tinydns),
already pointing those clients to nearby servers at DNS time
rather than having the application perform this routing.
If you need to check client information in logs
for abuse tracking,
one option is to collate PQConnect logs and application logs,
still without exposing client IP addresses to the application.
