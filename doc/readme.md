PQConnect is a new easy-to-install layer of Internet security.
PQConnect lets you take action right now on your computer
to address the threat of quantum attacks,
without waiting for upgrades in the applications that you are using.

PQConnect automatically applies post-quantum cryptography
from end to end between computers running PQConnect.
PQConnect adds cryptographic protection to unencrypted applications,
works in concert with existing pre-quantum applications to add post-quantum protection,
and adds a second application-independent layer of defense
to any applications that have begun to incorporate application-specific post-quantum protection.

VPNs similarly apply to unmodified applications,
and
[some](https://mullvad.net/en/blog/stable-quantum-resistant-tunnels-in-the-app)
[VPNs](https://rosenpass.eu/)
support post-quantum cryptography.
However, VPNs protect your traffic only between your computer
and the VPN proxies that you have configured your computer to contact:
VPN traffic is not encrypted end-to-end to other servers.
The
[advantage](crypto.html#bpn) of PQConnect
is that, once you have installed PQConnect on your computer,
PQConnect _automatically_ detects servers that support PQConnect,
and transparently encrypts traffic to those servers.
If you are a system administrator installing PQConnect on the server side:
configuring a server name to announce PQConnect support is easy.

## What to read next

The installation instructions for PQConnect are split between two scenarios.

If you are a system administrator
(for example, running a web server),
you should follow the
[installation instructions for sysadmins](sysadmin.html).
This covers setting up the PQConnect server software to handle incoming PQConnect connections from clients.

If you are a normal user
(for example, using a web browser),
you should follow the
[installation instructions for users](user.html).
This covers setting up the PQConnect client software to handle outgoing PQConnect connections to servers.

What about the combined scenario
that your computer is a client _and_ a server
(for example, your computer is running an SMTP server
and is also making outgoing SMTP connections)?
Then you should follow the
installation instructions for sysadmins.

## <a name="chat">Chat server</a>

We have very recently set up <https://zulip.pqconnect.net>
using Zulip, a popular open-source web-based chat system.
Feel free to join and discuss PQConnect there—you can be one of the first users!
Just click on "Sign up" and enter your email address.
Reports of what worked well and what didn't work so well
are particularly encouraged.

## Team

PQConnect team (alphabetical order):

* Daniel J. Bernstein,
  University of Illinois at Chicago, USA, and Academia Sinica, Taiwan

* Tanja Lange,
  Eindhoven University of Technology, The Netherlands, and Academia Sinica, Taiwan

* Jonathan Levin,
  Academia Sinica, Taiwan, and Eindhoven University of Technology, The Netherlands

* Bo-Yin Yang,
  Academia Sinica, Taiwan

The PQConnect software is from Jonathan Levin.

## Funding

This work was funded in part
by the U.S. National Science Foundation under grant 2037867;
the Deutsche Forschungsgemeinschaft (DFG, German Research Foundation)
under Germany's Excellence Strategy–EXC 2092 CASA–390781972 "Cyber Security in the Age of Large-Scale Adversaries";
the European Commision through the Horizon Europe program
under project number 101135475 (TALER);
the Dutch Ministry of Education, Culture, and
Science through Gravitation project "Challenges in Cyber Security - 024.006.037";
the Taiwan's Executive Yuan Data Safety and Talent
Cultivation Project (AS-KPQ-109-DSTCP);
and by the Academia Sinica Grand Challenge Projects AS-GCS-113-M07 and AS-GCP-114-M01.
"Any opinions, findings, and conclusions or recommendations expressed in this material are those
of the author(s) and do not necessarily reflect the views of the National Science Foundation"
(or other funding agencies).
