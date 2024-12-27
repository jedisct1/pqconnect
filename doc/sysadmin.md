These are instructions for adding PQConnect support to your existing server,
to protect connections from client machines that have installed PQConnect.
These instructions also cover PQConnect connections _from_ your server.

Prerequisites:
root on a Linux server (Arch, Debian, Gentoo, Raspbian, Ubuntu);
ability to edit DNS entries for the server name.

## <a name="quick-start">Quick start</a>

Here is how to download, install, and run the PQConnect server software.
Start a root shell and run the following commands:

    cd /root
    wget -m https://www.pqconnect.net/pqconnect-latest-version.txt
    version=$(cat www.pqconnect.net/pqconnect-latest-version.txt)
    wget -m https://www.pqconnect.net/pqconnect-$version.tar.gz
    tar -xzf www.pqconnect.net/pqconnect-$version.tar.gz
    cd pqconnect-$version
    scripts/install-pqconnect
    scripts/create-first-server-key
    scripts/start-server-under-systemd

Then edit the DNS entries for your server name,
following the instructions printed out by `create-first-server-key`.
This is what lets PQConnect clients
detect that your server supports PQConnect.

To also run the PQConnect client software:

    scripts/start-client-under-systemd

This has to be after `install-pqconnect` but can be before
`start-server-under-systemd`.
The client and server run as independent
`pqconnect-client` and `pqconnect-server` services.

## <a name="test">Testing</a>

The following steps build confidence that
your new PQConnect server installation
is properly handling PQConnect clients and non-PQConnect clients.
(If you are also running the PQConnect client software,
also try the [quick client test](user.html#quick-test)
and the [detailed client test](user.html#detailed-test).)

After `start-server-under-systemd`,
follow the instructions printed out by `create-first-server-key`,
but apply those instructions to a new `testing-pqconnect` server name in DNS
pointing to the same IP address,
without touching your normal server name.

On another machine running the
[PQConnect client software](user.html):
Test that `dig testing-pqconnect.your.server` sees a `10.*` address
instead of the server's actual public address.
Test that `ping -c 30 testing-pqconnect.your.server` works and sees a `10.*` address.

On the server,
run `journalctl -xeu pqconnect-server`
and look for a key exchange
with a timestamp matching
when the PQConnect client first accessed the server.
Optionally,
run a network sniffer on the server's public network interface
to see that the client's pings are arriving as UDP packets rather than ICMP packets.

Test the server's normal services from the client machine
and, for comparison, from a machine that isn't running PQConnect yet.
Note that web servers will typically give 404 responses
for the `testing-pqconnect` server name
(because that isn't the server's normal name),
but you can still see that the web server is responding.
Many other types of services will work independently of the name.

Finally,
move the `testing-pqconnect` configuration in DNS
to your normal server name,
and test again from both client machines.

## <a name="ports">PQConnect ports</a>

The PQConnect server needs clients to be able to reach it on two UDP ports:
a crypto-server port (42424 by default)
and a key-server port (42425 by default).
You may wish to pick other ports:
for example, ports below 1024
for <a href="security.html#port">port security</a>,
or ports that avoid restrictions set by
<a href="compat.html#firewall">external firewalls</a>.

To set, e.g., crypto-server port 624
and key-server port 584,
run

    scripts/change-server-cryptoport 624
    scripts/change-server-keyport 584

before running `start-server-under-systemd`,
and edit your DNS records to use the `pq1` name
printed out by the last script.

If you are running the PQConnect client software:
The PQConnect client uses port 42423 by default.
To set port 33333,
replace
`pqconnect-client`
with
`pqconnect-client -p 33333`
in `scripts/run-client-core`.

## <a name="server-in-a-bottle">Server-in-a-bottle mode</a>

The PQConnect server software supports a "server-in-a-bottle mode"
aimed at the following common situation:
You are running multiple virtual machines (VMs) on one physical machine (the host).
The VMs are managed by a hypervisor that tries to
[isolate](security.html#virtual)
each VM,
to protect the other VMs and the host.
The VMs communicate on a private network inside the host.
The host uses network-address translation
(NAT: e.g., `SNAT` or `MASQUERADE` with `iptables`,
along with `1` in `/proc/sys/net/ipv4/ip_forward`)
to resend outgoing network traffic from the VMs
to the Internet,
so that all of the VMs appear as the same IP address publicly.
Each VM is providing services on some ports on the public IP address:
e.g., the host is forwarding IMAP to one VM,
forwarding SMTP to another VM, etc.

What server-in-a-bottle mode does
is run a PQConnect server in its own VM
to protect connections to all of the other VMs
(and to any services that you are running outside VMs).
Compared to running PQConnect in each VM,
server-in-a-bottle mode has the following advantages:
PQConnect is installed just once on the machine;
there are only two new ports to configure for the machine,
instead of two new ports per VM;
to the extent that the hypervisor isolates VMs,
the other VMs are protected
against potential issues in the PQConnect software.

The steps to set up server-in-a-bottle mode are as follows.

**Create a VM.**
Create and start a new persistent VM
(called `pqserver`, for example)
running an OS compatible with the PQConnect software
(for example, Debian),
following your favorite procedure to create a new VM.
Give the VM its own address within the internal network.

**Ensure connectivity.**
Test that this VM can contact another VM
via the public IP address and port for the other VM.
(The whole point here is to have PQConnect protecting traffic
that it will deliver to the other VMs.)
If this test does not work,
presumably the port-forwarding configuration
is only for traffic arriving from the Internet;
add forwarding rules that also apply to traffic from this VM,
and try this test again.
You can do this without configuring anything outside the VM:
just copy the host's port-forwarding configuration into this VM,
adjust as necessary (for, e.g., the VM having different network-interface names,
and for copying any `PREROUTING` rules to `OUTPUT` rules),
and set up a script to copy and adjust any subsequent changes to the port-forwarding configuration.

**Choose ports.**
Choose two public ports for PQConnect.
Double-check that you are not using these ports for anything else:
for example,
you don't want to accidentally cut off
your existing SSH server on port 22.
For concreteness,
these instructions take crypto-server port 624
and key-server port 584.

**Forward packets for those ports into the VM.**
You'll want to be super-careful for this next step:
this step is working outside the VMs
(e.g., working on `dom0` under Xen).
This step assumes that the host is using `iptables` for packet management.
Run the following
both from the command line now
and in a boot script to apply after reboot:

    publicip=1.2.3.4
    pqserver=192.168.100.94
    for port in 584 624
    do
      for chain in PREROUTING OUTPUT
      do
        iptables -t nat -A $chain -p udp \
          -d $publicip --dport $port -j DNAT \
          --to-destination $pqserver:$port
      done
    done

Replace `1.2.3.4` with the host's public IP address,
and replace `192.168.100.94` with the VM's address on the host-internal network.

This `iptables` command configures DNAT
so that UDP packets (`-p udp`)
destined to these two ports (`--dport $port`)
on the public IP address (`-d $publicip`)
are resent to the same ports on the VM.

**Run PQConnect in the VM.**
Inside the VM,
follow the
[quick-start installation](#quick-start)
of the PQConnect server software,
but run

    scripts/change-server-cryptoport 624
    scripts/change-server-keyport 584
    echo 1.2.3.4 > /etc/pqconnect/config/host

right before running `start-server-under-systemd`.
As before, replace `1.2.3.4` with the host's public IP address.

This sets up the server to run on the specified ports inside the VM
(you can also use ports different from the public ports if you want,
as long as you forward the public ports appropriately),
and to forward decrypted packets to the public IP address.

**Forward decrypted packets out of the VM.**
Inside the VM,
install `iptables` for packet management,
and run the following
(with `enX0` replaced by the VM's name for its network interface),
both from the command line now
and in a boot script to apply after reboot:

    sysctl -w net.ipv4.ip_forward=1
    for proto in tcp udp icmp
    do
      iptables -t nat -A POSTROUTING -p $proto \
        -s 10.42.0.0/16 -o enX0 -j MASQUERADE \
        --to-ports 40000-50000
    done

This `iptables` rule arranges for PQConnect's decrypted packets
to be delivered to `dom0`
in a way that allows PQConnect to see replies to those packets.
Specifically, the PQConnect server software
chooses various `10.42.*` addresses to send decrypted packets to the public IP address;
this rule will rewrite those packets
as coming from `192.168.100.94` (using port numbers to track the original addresses),
and will undo this rewriting for packets sent in reply.
The `10.42` is a default in the PQConnect server software;
it's used only inside the VM,
so it isn't an address you have to change for your configuration.

**Test.**
Now [test PQConnect](#test)
using a new `testing-pqconnect` server name.
Then edit DNS to announce PQConnect support
on whichever names are used for the services provided by this machine.
If the DNS names for some VMs are managed by other people,
let those people know that they can enable PQConnect support
for those names by simply modifying the DNS entries.
You don't have to upgrade all of the names at once.

## <a name="client-in-a-bottle">Client-in-a-bottle mode</a>

The PQConnect client software supports a "client-in-a-bottle mode"
that runs in a VM to protect outgoing connections from the whole machine,
analogous to the
<a href="#server-in-a-bottle">server-in-a-bottle mode</a>
for the server software.
Documentation coming soon!
