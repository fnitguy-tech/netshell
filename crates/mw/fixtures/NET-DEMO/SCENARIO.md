# NET-DEMO: fictional uplink migration at SITE-A

Bundled pre/post captures so `python3 scripts/demo.py` can run the whole
compare pipeline with no devices. Everything here is made up: RFC 5737 /
RFC 6598 addresses, documentation ASNs (64496–64511), invented serials.

**The change:** SITE-A moves its internet transit from ISP-A (Et49/1,
AS64496) to ISP-B (Et50/1, AS64497).

| Device       | Platform | What the postcheck should show |
|--------------|----------|--------------------------------|
| SITE-A-SW-1  | EOS      | ISP-A peer shut down (Attention), ISP-B peer added and established, default route moves to Et50/1, VLAN 240 added, config diff |
| SITE-A-SW-2  | EOS      | iBGP prefix count 812 → 815, VLAN 240 added, config diff |
| SITE-B-SW-1  | EOS      | Nothing: only uptime, counters, and OSPF dead-timer moved, all of which the normalizer strips |
| SITE-A-FW-1  | PAN-OS   | One new security rule in `show config running`; route ages and content versions ignored |
