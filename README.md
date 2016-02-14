# Musical Invention
Linux firewall whitelist, based on domain names. Opens the firewall after a successful DNS lookup to an approved host, then closes it shortly afterwards.

Programs should not need to be modified to run under Musical Invention.

## TODO list (do not use until all are ticked)

- [X] Find needed technologies: Send packets to userspace (iptables -j QUEUE), change iptables rules from C (system("iptables"))
- [ ] Parse DNS query
- [ ] Parse DNS reply
- [ ] DNS over TCP
- [ ] Remove stale iptables rules after a while
- [ ] Make it configurable

## Setup

Dependencies: libnetfilter_queue, /sbin/iptables (Debian names: libnetfilter-queue-dev, iptables).

I'd prefer figuring out the kernel protocols and implementing that myself (I generally dislike
dependencies, even if taking them would make the program smaller), but the netfilter and iptables
APIs are undocumented, and strace and the source codes aren't enough for me to figure them out.

To use Musical Invention, you must set up some iptables rules:
- Forward all DNS traffic to Musical Invention.
- Set up a filter chain where Musical Invention can append the rules.
- Set up rules for allowing localhost, and whatever else is in your /etc/hosts.
- Set a rule to block by default. No point allowing traffic to certain domains, then allowing everything else too.

It may look like Musical Invention can be used to blacklist domain names too, but Musical Invention
is designed to be as strict a whitelist as possible - which makes it too loose to use as a blacklist.
For example, an attacker can get past that by waiting between the lookup and the request, or
connecting to an IP directly without looking it up.

To get started, you can use these commands:

```
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0
iptables -A INPUT -p tcp --sport 53 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p tcp --dport 53 -j NFQUEUE --queue-num 0

iptables -N MUSICAL
iptables -A OUTPUT -j MUSICAL

iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT

iptables -P OUTPUT REJECT

musical-invention /etc/musical-invention.conf
```

If your setup is more complicated (if you're using an outbound firewall, it is), feel free to adjust.

## Config example

```
# Comments are allowed with #. Blank and whitespace-only lines are also fine.
example.com                              # Basic entry. Everyone can access example.com on any port and protocol, but only after a successful DNS lookup.
example.com proto=tcp                    # Reject UDP and ICMP traffic (including ping) to this host. Options like that must be after the domain name.
example.com proto=tcp port=80            # Allow only TCP port 80. ICMP traffic is consided to be port 0.
example.com proto=tcp,udp                # Allow TCP and UDP, but not ICMP.
irc.example.com proto=tcp port=6667-6669 # Allow multiple TCP ports. The range is inclusive on both sides.
.example.com                             # Allow all subdomains of example.com, including multi-level (foo.bar.example.com). Doesn't allow example.com itself, but you can always add an extra rule for that.
example.com ip=93.184.216.34             # Allow only if example.com points to that IP address.
example.com ip=93.184.0.0/16             # Allow only if example.com points to that subnet.
example.com user=www-data                # Allow only for this user. Note that DNS lookups are allowed for everyone; others just can't communicate with the target.
# To allow everything for a user, put [iptables -A OUTPUT -m owner --uid-owner (user) -j ACCEPT] before NFQUEUEing the DNS requests.
* queue=0                                # Tells which iptables NFQUEUE to listen to. Must have a * in the domain name field.
* chain=MUSICAL target=ACCEPT            # Tells which iptables chain to write the rules to, and what target to use. You can put a custom chain that logs then accepts here.
example.com target=LOGACCEPT             # Sets the target chain for this specific rule.
example.com delay=300                    # Tells how long to leave the port open after a successful lookup. Domain name can be * to set the default, or you can put this on any valid rule.
# Don't just set it to one second, because that's how long it takes to open the connection; DNS lookups are often cached, and if the cache lasts longer than this timer, successive connections will fail.
* delay=TTL                              # This special value tells Musical Invention that the delay should be the DNS TTL value. This is often a day, and is not recommended unless you're trying to run a program that caches its lookups.
* ns=192.168.1.1/32                      # Tells which nameservers are approved. Multiple of these may exist. Useful if you're using a DNSBL for any purpose.
* ns=auto                                # Makes Musical Invention autodetect your nameserver, by doing a lookup for a randomly generated domain name and checking what IP addresses the request ends up going to. Can not be used together with manually approved nameservers.
```

The default values are queue=0 chain=MUSICAL target=ACCEPT delay=10 ns=auto, and no approved hostnames.

## Limitations

Only TCP, UDP and ICMP PING are supported. Only IPv4 is supported (though IPv6 should be easy to add). Only Linux hosts are supported. VPNs are unlikely to work, and guaranteed to not do what's intended.

## Security model

Musical Invention assumes that the attacker
- Is aware of Musical Invention and that it's used here
- Has full access to all system configuration, including but not limited to iptables and Musical Invention
- Can execute a hostile program of his choosing, which may be crafted using knowledge of the system config
- Has the goal of transfering any amount of data in or out of the system; this data is not part of the chosen program, and is not part of the known config
and that the attacker can not
- Become root; root can easily set the iptables policy to accept all
- Compromise the local DNS resolver; forged DNS answers will trick Musical Invention into opening an incorrect port
- Bind to port 53 on the loopback interface; binding port 53 means you are the DNS resolver and can send forged answers
- Control an approved nameserver and send forged answers
- Send forged packets from the outside; if that's possible, the attacker can send a DNS query with known sequence numbers and source port, and forge a response before the real one arrives
- Control some content on any approved host, for example via non-approved subdomains on the same IP; Musical Invention can't see which subdomain you're trying to talk to

<br>

And the name? I just accepted one of GitHub's silly "Need inspiration? How about foo-bar." suggestions.
