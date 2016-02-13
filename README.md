# Musical Invention
Linux firewall whitelist based on domain names. Opens the firewall after a successful DNS lookup to an approved host, then closes it shortly afterwards.

Programs generally don't need to be modified to run under Musical Invention.

## TODO list (do not use until all are ticked)

- [ ] Find needed technologies: Send packets to userspace (iptables -j QUEUE), change iptables rules from C (unknown)
- [ ] Parse DNS query
- [ ] Parse DNS reply
- [ ] DNS over TCP
- [ ] Remove stale iptables rules after a while
- [ ] Make it configurable

## Setup

Dependencies: libnetfilter_queue, /sbin/iptables (Debian names: libnetfilter-queue-dev, iptables).

I'd prefer figuring out the kernel protocols and implementing that myself, but the netfilter and
iptables APIs are undocumented, and strace and the source codes aren't enough for me to figure them out.

To use Musical Invention, you must set up some iptables rules:
- Forward all DNS traffic to Musical Invention.
- Set up a filter chain where Musical Invention can append the rules.
- Set up rules for allowing localhost, and whatever else is in your /etc/hosts.
- Set a rule to block anything else. No point allowing traffic to certain domains, then allowing everything else too.

It may look like Musical Invention can be used to blacklist domain names too, but it's not designed
for that, and a crafty attacker can get past that by waiting between the lookup and the request, or
transferring the IP in another way. Musical Invention is a whitelist, not a blacklist.

For a basic setup, you can use these commands; feel free to adjust if your setup is more complicated:

```
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0
iptables -A INPUT -p tcp --sport 53 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p tcp --dport 53 -j NFQUEUE --queue-num 0

iptables -N MUSICAL
iptables -A OUTPUT -j MUSICAL

iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT --queue-num 0

iptables -P OUTPUT REJECT

musical-invention /etc/musical-invention.conf
```

## Config example

```
example.com                              # Basic entry. Everyone can access example.com on any port and protocol, but only after a successful DNS lookup.
# Comments are allowed with #. Blank and whitespace-only lines are also fine.
example.com proto=tcp                    # Reject UDP and ICMP traffic (including ping) to this host. Options like that must be after the domain name.
example.com proto=tcp port=80            # Allow only TCP port 80. ICMP has no ports.
example.com proto=tcp,udp                # Allow TCP and UDP, but not ICMP.
irc.example.com proto=tcp port=6667-6669 # Allow multiple TCP ports. The range is inclusive on both sides.
.example.com                             # Allow all subdomains of example.com, including multi-level (foo.bar.example.com). Doesn't allow example.com itself, but you can always add an extra rule for that.
example.com ip=93.184.216.34             # Allow only if example.com points to that IP address.
example.com ip=93.184.0.0/16             # Allow only if example.com points to that subnet.
example.com user=www-data                # Allow only for this user. Note that DNS lookups are allowed for everyone; others just can't communicate with the target.
# To allow everything for a user, put [iptables -A OUTPUT -m owner --uid-owner (user) -j ACCEPT] before NFQUEUEing the DNS request.
* queue=0                                # Tells which iptables QUEUE to listen to. Must have a * in the domain name field.
* chain=MUSICAL target=ACCEPT            # Tells which iptables chain to write the rules to, and what target to use. You can put a custom chain that logs then accepts here.
example.com delay=300                    # Tells how long to leave the port open after a successful lookup. Domain name can be * to set the default, or you can put this on any valid rule.
# Don't just set it to one second, because that's how long it takes to open the connection; DNS lookups are often cached, and if the cache lasts longer than this timer, successive connections will fail.
* delay=TTL                              # This special value tells Musical Invention that the delay should be the DNS TTL value.
```

The default values are queue=0 chain=MUSICAL accept=ACCEPT delay=TTL, and an empty whitelist.

## Limitations

Only TCP, UDP and ICMP PING are supported. Only IPv4 is supported. Only Linux hosts are supported.



And the name? I just accepted one of GitHub's silly "Need inspiration? How about foo-bar." suggestions.
