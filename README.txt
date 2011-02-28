IPF - IP Fragment Handling Module

Is a independent IP Fragment Reassembler, capable of doing IPv4 and IPv6
reassebly.

One of the major problems is the follwoing: a middle box should never ever
reassembly packets. But we are enforced to reassembly packets because the
packet classifier requires a complete packet. For example: a IP/TCP packet
which in turn is fragmented into 10 packets contains only one TCP header,
all other packets contains no TCP header. The missing TCP header in turn
restrict the packet classifier to work

Note on fact: for the case that one of n fragments is missing after
max_time seconds all fragments are forwarded to the next processing unit.
It may be the case that one fragment is lost in the path from the sender
to us and we delay unlimited all packets. An potential attacker can drop
one fragment and this module in turn drops all remaining fragments - this
should not happend. Therefore after max_time we start to forward all
fragments.

Last but not least: the IP Fragment Handling Module is not per see evil.
On the contrary it is the Packet Classifier which operates on Transport
Level Fields which are not present at middle boxes. This is the Dilema.
