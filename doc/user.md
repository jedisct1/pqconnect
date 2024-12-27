These are instructions for setting up the PQConnect client software.
This automatically protects outgoing connections from your machine
to servers that support PQConnect.

Prerequisites:
root on a Linux machine (Arch, Debian, Gentoo, Raspbian, Ubuntu).
The software does not support other operating systems yet, sorry.

## <a name="quick-start">Quick start</a>

Here is how to download, install, and run the PQConnect client software.
Start a root shell and run the following commands:

    cd /root
    wget -m https://www.pqconnect.net/pqconnect-latest-version.txt
    version=$(cat www.pqconnect.net/pqconnect-latest-version.txt)
    wget -m https://www.pqconnect.net/pqconnect-$version.tar.gz
    tar -xzf www.pqconnect.net/pqconnect-$version.tar.gz
    cd pqconnect-$version
    scripts/install-pqconnect
    scripts/start-client-under-systemd

That's it: you're now running PQConnect.

## <a name="quick-test">Quick test</a>

Try `curl https://www.pqconnect.net/test.html`;
or click on
<https://www.pqconnect.net/test.html>
from a browser running on the same machine.
Your machine running PQConnect will say
`Looks like you're connecting with PQConnect. Congratulations!`,
where a machine without PQConnect would say
`Looks like you aren't connecting with PQConnect`.

Also try connecting to a non-PQConnect server
(for example, <https://testwithout.pqconnect.net>)
to see that non-PQConnect connections work normally.

## <a name="detailed-test">Detailed test</a>

If you have `dig` installed:
Try `dig +short www.pqconnect.net`.
Your machine running PQConnect will say

    pq1u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1.pqconnect.net.
    10.43.0.2

(or possibly another `10.*` address)
where a machine without PQConnect would say

    pq1u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1.pqconnect.net.
    131.155.69.126

(where 131.155.69.126 is the actual `www.pqconnect.net` IP address).

Try `ping -nc 30 www.pqconnect.net`.
Your machine will print `bytes from` lines such as

    64 bytes from 10.43.0.2: icmp_seq=2 ttl=64 time=120 ms

again showing a `10.*` address.

If you have a network sniffer such as `tcpdump` installed,
start sniffing the network for packets to and from IP address 131.155.69.126:

    tcpdump -Xln host 131.155.69.126 > tcpdump-log &

Use `wget` to retrieve a web page via HTTP,
first without PQConnect and then with PQConnect:

    wget -O test1.html http://testwithout.pqconnect.net/test.html
    wget -O test2.html http://www.pqconnect.net/test.html

Then kill the `tcpdump` job and scroll through the `tcpdump-log` output.
You will see that the first connection uses TCP packets
to and from `131.155.69.126.80`, meaning port 80 of IP address 131.155.69.126,
with an obviously unencrypted request
(search for `GET` and you will see `GET /test.html`, `Host: testwithout.pqconnect.net`, etc.)
and an obviously unencrypted response,
while the second connection uses
encrypted UDP packets
to and from port 42424 of IP address 131.155.69.126.

## <a name="non-systemd">Non-systemd alternatives</a>

Running the client under systemd
is currently recommended
because it applies some sandboxing,
but you can instead run

    scripts/run-client &

to more directly run the client.
Logs are then saved in `pqconnect-log` in the same directory.
If the computer reboots,
the client will not restart
unless you run `scripts/run-client` again.
