Matei Hriscu, 321 CA

# Router Dataplane

Before processing packets, the router generates its routing table from the file
provided as a command-line argument. To perform longest prefix match operations
in constant time, the router stores this table as an internal trie.

Once the initialization is complete, the router begins processing packets that
have it as their level 2 destination.

## ARP Packets:

If an ARP request packet targets the router at level 3, the router responds with
an ARP reply containing its MAC address according to the ARP standard.
Conversely, if the packet is an ARP reply, the sender's MAC address is stored in
the router's ARP cache.

## IP Packets:

When an IP packet is received, the router first performs multiple checks to
ensure it is routed correctly. The checksum is verified, as it invalidates the
entire packet if incorrect. If the checksum is correct, the router checks if it
is the level 3 destination. If so, the router will only respond if the packet is
an ICMP Echo Request, otherwise it will drop the packet.

If the router is not the destination, it checks the TTL and drops packets with a
TTL value of 1 or less, as such packets are dropped at the next hop anyway. If
all checks pass, the router finds the next hop based on the longest prefix match
in the routing table. Thanks to the trie, this operation is performed in
constant time. The router then updates the packet (decreasing the TTL and
updating the level 2 header) before sending it to the appropriate interface. If
the router cannot find the MAC address of the next hop, it issues an ARP request
and caches the packet until it receives a reply. 

## ICMP Packets:

When an ICMP packet is targetted at the router, the router will respond to it if
it is an Echo Request, and will drop it otherwise. Also, when IP packets are
dropped by the router for various reasons, such as TTL expiration or not
matching any next hop, the router will send an ICMP packet with the appropriate
code back to the original sender to notify them that their packet has been
dropped. This is done efficiently by transforming the received packet in-place. 