This page explains PQConnect's top three cryptographic goals,
and various aspects of how PQConnect aims to achieve those goals.
There is a
[separate page](security.html)
looking more broadly at security.

## <a name="encryption">Priority 1: post-quantum encryption</a>

Attackers are
[carrying out mass surveillance of Internet traffic](https://www.theguardian.com/uk-news/2021/may/25/gchqs-mass-data-sharing-violated-right-to-privacy-court-rules).
They are
[saving encrypted data to break later](https://www.forbes.com/sites/andygreenberg/2013/06/20/leaked-nsa-doc-says-it-can-collect-and-keep-your-encrypted-data-as-long-as-it-takes-to-crack-it/).
They are years ahead of the public in
[investing in quantum computers](https://www.washingtonpost.com/world/national-security/nsa-seeks-to-build-quantum-computer-that-could-crack-most-types-of-encryption/2014/01/02/8fff297e-7195-11e3-8def-a33011492df2_story.html).
The ciphertexts we send are irrevocably shown to any attackers monitoring the network;
we cannot retroactively improve the encryption of that data.

The top priority for PQConnect
is to switch as much Internet traffic as possible,
as quickly as possible,
to high-security end-to-end post-quantum encryption.

To the extent that some applications have already been
rolling out post-quantum encryption, great!
PQConnect adds another layer of defense in case that fails,
a layer systematically designed for high security.
But the more obvious benefit of PQConnect
is for applications that are still using pre-quantum encryption
or no encryption at all.
PQConnect provides a fast application-independent path to post-quantum cryptography.

## <a name="authentication">Priority 2: post-quantum authentication</a>

Another important goal of PQConnect
is to switch as much Internet traffic as possible,
as quickly as possible,
to high-security end-to-end post-quantum _authentication_.

The urgency of post-quantum authentication is not as obvious
as the urgency of post-quantum encryption.
Consider,
for example,
an application relying on pre-quantum signatures for authentication.
Assume that the application is upgraded so that all verifiers accept post-quantum signatures,
and then upgraded to replace all generated pre-quantum signatures with post-quantum signatures,
and then upgraded so that verifiers stop accepting pre-quantum signatures,
with all of these upgrades deployed by all signers and verifiers
before the attacker has a quantum computer.
There will then be no verifiers accepting the attacker's forged pre-quantum signatures.

However,
the timeline for upgrades is variable and often extremely slow.
For example,
within web pages loaded by Firefox,
the [percentage using HTTPS](https://letsencrypt.org/stats/)
was around 30% in 2014, around 80% in 2020, and still around 80% in 2024.
There are clear risks that,
when the first public demonstrations of quantum attacks appear,
many applications will still be using pre-quantum cryptography,
while real quantum attacks will already have been carried out in secret.
Starting earlier on upgrades will reduce the damage.

## <a name="key-erasure">Priority 3: fast post-quantum key erasure</a>

Sometimes a user's device is stolen or otherwise compromised by an attacker.
Perhaps this allows attackers to find decryption keys inside the device,
and to use those keys to decrypt ciphertexts that the attacker previously recorded.

Of course,
the big problem here is that secrets stored on a user device
were exposed in the first place.
What one wants is better protection for all data stored on the device.
However,
in case that protection fails,
the damage may be reduced if keys are preemptively erased.

PQConnect sets a goal of having each ciphertext no longer decryptable 2 minutes later,
even if the client and server devices are subsequently compromised
by an attacker also having a quantum computer.
Concretely, PQConnect encrypts each ciphertext using a post-quantum key
that is erased by the client and by the server within 2 minutes.
This erasure happens _within_ each PQConnect tunnel,
no matter how long the tunnel lasts.

For comparison,
the "ephemeral" options in TLS are often claimed to provide
["Perfect Forward Secrecy"](https://datatracker.ietf.org/doc/html/rfc5246),
but these options still allow ciphertexts to be decryptable for 
[as long as a TLS session lasts](https://www.imperialviolet.org/2013/06/27/botchingpfs.html).
A [2016 study](https://jhalderm.com/pub/papers/forward-secrecy-imc16.pdf) found that
"connections to 38% of Top Million HTTPS sites are vulnerable to decryption if the server is compromised up to 24 hours later, and 10% up to 30 days later".
Current security guides that ask TLS applications to
[disable session resumption](https://docs.veracode.com/r/harden-tls-session-resumption)
do not prevent sessions from lasting for hours or longer.

## <a name="full">Full-packet encryption</a>

PQConnect encrypts the complete packets sent by applications,
including protocol headers and port numbers.
Attackers may be able to deduce
the same information by analyzing metadata
such as the timings and lengths of packets,
but this is not a reason to simply give the data away.

## <a name="bpn">VPNs and BPNs</a>

VPNs typically share PQConnect's features
of being application-independent and encrypting full packets.
However,
VPNs generally do not provide end-to-end security.
A client sets up a VPN to encrypt traffic to a VPN proxy,
but then traffic is exposed at the VPN proxy,
and at every point between the VPN proxy and the ultimate server.

It is possible to manually configure typical VPN software
so that a connection to `www.your.server`
goes through a VPN tunnel to `www.your.server`,
a connection to `www.alices.server`
goes through a VPN tunnel to `www.alices.server`,
etc.,
when this is supported by the servers.
PQConnect _automates_ the processes of announcing server support
and of creating these tunnels.

In English,
"boring a tunnel" means creating a tunnel by digging, typically with a tool.
PQConnect is a "BPN": a "Boring Private Network".

The PQConnect mascot is a Taiwanese pangolin.
Pangolins dig tunnels and are protected by their armor.
The Mandarin name for pangolins is 穿山甲,
literally "pierce mountain armor".
Legend says that pangolins travel the world through their tunnels.

There is another use of the word "boring" in cryptography:
["boring cryptography"](https://cr.yp.to/talks.html#2015.10.05)
is cryptography that simply works, solidly resists attacks,
and never needs any upgrades.
PQConnect also aims to be boring in this sense.

## <a name="double">Double public-key encryption: ECC+PQ</a>

To the extent that applications have upgraded to post-quantum public-key encryption,
they are normally using it as a second layer
on top of pre-quantum public-key encryption (typically X25519),
rather than as a replacement for pre-quantum public-key encryption.
This [reduces the damage](security.html#non-nocere)
in case of a security failure in the post-quantum software:
the impact is delayed until the attacker has a quantum computer.

PQConnect follows this approach.
One difference in details is that
PQConnect replaces typical concatenated encryption
with nested encryption to reduce attack surface.

## <a name="mceliece">Conservative public-key encryption: McEliece</a>

PQConnect does not use the presence of an ECC backup
as an excuse for risky PQ choices.
A devastating PQ failure would mean that goal #1 is not achieved.

The foundation of security in PQConnect is the
[Classic McEliece](https://classic.mceliece.org)
encryption system at a
[very high security level](https://cat.cr.yp.to/cryptattacktester-20240612.pdf#page.28),
specifically `mceliece6960119`;
the software uses
[libmceliece](https://lib.mceliece.org).
Among proposals for post-quantum public-key encryption,
the McEliece cryptosystem is unique in how strong its security track record is:
more than
[50 papers](https://isd.mceliece.org) attacking the system since 1978
have produced
[only tiny changes in the McEliece security level](https://cr.yp.to/talks/2024.09.17/slides-djb-20240917-mceliece-16x9.pdf#page.16).
Classic McEliece is also used in
the
[Mullvad](https://mullvad.net/en/blog/stable-quantum-resistant-tunnels-in-the-app)
and
[Rosenpass](https://rosenpass.eu/)
VPNs, and in various
[other applications](https://mceliece.org).

Each PQConnect server has a long-term 1MB Classic McEliece key
that it sends out upon request.
To prevent amplification,
PQConnect pads the request to 1MB.
This cost is only per-client, not per-tunnel or per-connection.
The PQConnect client software generates and saves many Classic McEliece ciphertexts
so that it can immediately generate fresh tunnels to the server
without re-requesting the key;
an alternative would be to save the full key.

Of course,
if your smartphone's mobile-data plan
has a 10GB-per-month data cap,
and this month your phone wants to contact
5000 PQConnect servers that it has never talked to before,
then you'll have to get on Wi-Fi.

## <a name="enc-auth">Public-key encryption for authentication</a>

PQConnect uses Classic McEliece
not just to protect the confidentiality of user data
but also to protect the user data against forgeries.
The client sends a ciphertext to the server's public key
to establish a secret session key known to the client and server.
The session key is the key for an authenticated cipher
that protects each packet of user data.

Reusing encryption for authentication
avoids the need for a separate signature system.
Some references:
[1998](https://eprint.iacr.org/1998/009),
[2009](https://dnscurve.org),
[2016](https://cr.yp.to/talks.html#2016.02.24),
[2018](https://www.pqcrypto.eu/deliverables/d2.5.pdf),
[2020](https://eprint.iacr.org/2020/534).

## <a name="auth-pk">Authenticating public keys</a>

TLS relies on DNS to be secure.
An attacker that controls the DNS records for `www.your.server`
(for example,
an attacker that compromises the root DNS servers,
that exploits continuing holes in the deployment of cryptography for DNS,
or that uses a quantum computer to break pre-quantum cryptography used for DNS)
can obtain `www.your.server` certificates from Let's Encrypt
and can then freely impersonate `www.your.server`,
even if applications stop trusting all CAs other than Let's Encrypt.
"Certificate transparency" sees the new certificate but does not stop the attack.

Similarly,
an attacker controlling the DNS records for `www.your.server`
can turn off PQConnect for `www.your.server`,
or replace the legitimate PQConnect public key for `www.your.server`
with the attacker's public key.

The PQConnect protocol supports three approaches to stopping this attack.
First,
the PQConnect protocol is capable of protecting DNS itself.
We are planning more documentation and software for this;
stay tuned!

Second,
to the extent that other security mechanisms are deployed successfully for DNS,
they also protect PQConnect's server announcements.

Third,
the PQConnect protocol lets you use a high-security name that includes your server's public key.
For example,
instead of linking to
[https://www.pqconnect.net](https://www.pqconnect.net),
you can link to a
[high-security PQConnect name](https://pq1u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1.yp.to)
for the same server,
as long as the application does not impose severe length limits (in, e.g., certificates).
Some client-side software steps are necessary to make sure that
all paths for attackers to substitute other names are closed off
(e.g., the key extracted from the PQConnect name
has to override any keys provided by CNAMEs,
and DNS responses sent directly to applications have to be blocked),
but this is conceptually straightforward.

## <a name="ntruprime">Public-key encryption for fast key erasure: NTRU Prime</a>

Beyond encrypting data to the server's long-term McEliece public key,
a PQConnect client
applies another layer of encryption to a short-term public key provided by the server,
to enable fast key erasure.

This short-term public key uses a small-key lattice-based cryptosystem.
This choice has the advantage of reducing per-tunnel costs,
although this does not matter when there is a large amount of data per tunnel.
The disadvantage is that
lattice-based cryptography has
[higher security risks](https://ntruprime.cr.yp.to/warnings.html)
than the McEliece cryptosystem,
and a break of the lattice-based cryptosystem would mean that keys are not erased,
although this does not matter unless the attacker also steals secrets from the device.

Trigger warning:
If you find patents traumatic,
or if your company has a policy to not learn about patents,
please stop reading at this point.

[Unfortunately](https://patents.google.com/patent/US9094189B2/en),
[lattice](https://patents.google.com/patent/US9246675B2/en)-[based](https://patents.google.com/patent/CN107566121A/en)
[cryptography](https://patents.google.com/patent/CN108173643A/en)
[is](https://patents.google.com/patent/KR101905689B1/en)
[a](https://patents.google.com/patent/US11050557B2/en)
[patent](https://patents.google.com/patent/US11329799B2/en)
[minefield](https://patents.google.com/patent/EP3698515B1/en).
NIST has published
[edited excerpts of a license](https://web.archive.org/web/20240331123147/https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/selected-algos-2022/nist-pqc-license-summary-and-excerpts.pdf)
that appears to cover two older patents (9094189 and 9246675),
but the license is only for Kyber;
meanwhile another patent holder, Yunlei Zhao,
has
[written](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/Fm4cDfsx65s/m/F63mixuWBAAJ)
that "Kyber is covered by our patents".

Fortunately,
there is one lattice-based cryptosystem old enough for its patent to have
[expired](https://patents.google.com/patent/US6081597A),
namely NTRU.
Various security problems were discovered the original version of NTRU,
but all of the known issues
(and some other issues that make audits unnecessarily difficult)
are addressed by tweaks in
[Streamlined NTRU Prime](https://ntruprime.cr.yp.to) (`sntrup`),
which was published in
[May 2016](https://ntruprime.cr.yp.to/ntruprime-20160511.pdf).
There were not many post-quantum patents at that point.
The current version of `sntrup` differs only in
some small tweaks to serialization and hashing published in
[April 2019](https://ntruprime.cr.yp.to/nist/ntruprime-20190330.pdf),
and patent searches have found no issues here.

Streamlined NTRU Prime was added to TinySSH and OpenSSH in 2019,
and was made default in OpenSSH in [2022](https://www.openssh.com/txt/release-9.0),
with no reports of any problems.
PQConnect also uses Streamlined NTRU Prime,
specifically `sntrup761`.
The software uses [libntruprime](https://libntruprime.cr.yp.to).

## <a name="verif">Formal verification</a>

Most of the PQConnect security analysis so far is manual,
but symbolic security analysis of one component of PQConnect, namely the handshake,
is within reach of existing automated tools
and has been carried out using an existing prover,
namely Tamarin.
Running

    scripts/install-tamarin
    scripts/run-tamarin

inside the PQConnect software package
will install Tamarin and verify the handshake.
See Section V of the
[NDSS 2025 paper](papers.html)
for more information.
