#include <bits/stdc++.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <netinet/in.h>
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
using namespace std;

#define MAX_RTABLE_SIZE 1'000'000

typedef array<uint8_t, ETH_ALEN> mac;

class Trie {
private:
	struct Node {
		bool is_end = false;
		array<Node*, 2> next {nullptr, nullptr};
		route_table_entry data;
	};

	Node *root = new Node;

public:
	void insert(route_table_entry e) {
		uint32_t key = ntohl(e.prefix & e.mask);
		size_t key_len = __builtin_popcount(e.mask);
		Node *current = root;

		for (size_t i = 0, bit = 1 << 31; i < key_len; ++i, bit >>= 1) {
			if (!current->next[(key & bit) != 0])
				current->next[(key & bit) != 0] = new Node;
			current = current->next[(key & bit) != 0];
		}

		current->data = e;
		current->is_end = true;
	}

	optional<route_table_entry> match(in_addr_t ip) {
		optional<route_table_entry> ans;
		Node *current = root;
		in_addr_t key = ntohl(ip);

		for (uint32_t bit = 1 << 31; bit; bit >>= 1) {
			if (!current->next[(key & bit) != 0])
				break;
			
			current = current->next[(key & bit) != 0];

			if (current->is_end)
				ans = current->data;
		}

		return ans;
	}
} route_table_trie;

struct packet {
	int interface;
	char *buf;
	size_t len;

	packet(int interface, char *buf, size_t len)
		: interface(interface), len(len) {
		this->buf = new char[len];
		memcpy(this->buf, buf, len);
	}
};

mac broadcast_mac {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
vector<route_table_entry> route_table;
unordered_map<in_addr_t, mac> arp_cache;
unordered_map<in_addr_t, vector<packet>> arp_queue;

void generate_route_table(const char *file) {
	route_table_entry *tmp = new route_table_entry[MAX_RTABLE_SIZE];
	int entries = read_rtable(file, tmp);

	for (int i = 0; i < entries; ++i)
		if ((tmp[i].prefix & tmp[i].mask) == tmp[i].prefix)
			route_table_trie.insert(tmp[i]);

	delete[] tmp;
}

bool verify_ip_checksum(iphdr *ip_hdr) {
	uint16_t received_sum = ntohs(ip_hdr->check);

	ip_hdr->check = 0;
	return checksum((uint16_t *)ip_hdr, sizeof(iphdr)) == received_sum;
}

optional<pair<in_addr_t, int>> find_next_hop(in_addr_t daddr) {
	optional<route_table_entry> ans = route_table_trie.match(daddr);

	if (ans.has_value())
		return make_pair(ans.value().next_hop, ans.value().interface);
	return nullopt;
}

void send_packet(int interface, char *buf, size_t len) {
	size_t sent = 0;
	
	while (sent < len) {
		int rc = send_to_link(interface, buf + sent, len - sent);

		DIE(rc < 0, "send_to_link");
		sent += rc;
	}
}

void send_arp_request(in_addr_t ip, int interface) {
	char request[sizeof(ethhdr) + sizeof(arp_header)];
	ethhdr *eth_hdr = (ethhdr *)request;
	arp_header *arp_hdr = (arp_header *)(request + sizeof(ethhdr));

	get_interface_mac(interface, eth_hdr->h_source);
	memset(eth_hdr->h_dest, 0xFF, ETH_ALEN);
	eth_hdr->h_proto = htons(ETH_P_ARP);

	arp_hdr->htype = htons(ARPHRD_ETHER);
	arp_hdr->ptype = htons(ETH_P_IP);
	arp_hdr->hlen = ETH_ALEN;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(ARPOP_REQUEST);
	memcpy(arp_hdr->sha, eth_hdr->h_source, ETH_ALEN);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	arp_hdr->tpa = ip;

	send_packet(interface, request, sizeof(ethhdr) + sizeof(arp_header));
}

void handle_icmp_packet(char *buf) {
	icmphdr *icmp_hdr = (icmphdr *)(buf + sizeof(ethhdr) + sizeof(iphdr));
	uint16_t received_sum = ntohs(icmp_hdr->checksum);

	icmp_hdr->checksum = 0;
	if (received_sum != checksum((uint16_t *)icmp_hdr, sizeof(icmphdr))) {
		cerr << "Packet dropped: invalid ICMP checksum\n";
		return;
	}

	if (icmp_hdr->type != ICMP_ECHO) {
		cerr << "Packet dropped: invalid ICMP code\n";
		return;
	}

	icmp_hdr->type = ICMP_ECHOREPLY;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(icmphdr)));

	iphdr *ip_hdr = (iphdr *)(buf + sizeof(ethhdr));

	swap(ip_hdr->saddr, ip_hdr->daddr);
	ip_hdr->ttl = 64;
}

void icmp_err(char *buf, uint8_t type) {
	cerr << "here\n";

	iphdr *ip_hdr = (iphdr *)(buf + sizeof(ethhdr));
	icmphdr *icmp_hdr = (icmphdr *)(buf + sizeof(ethhdr) + sizeof(iphdr));

	memcpy(icmp_hdr + 1, ip_hdr, 8);

	swap(ip_hdr->saddr, ip_hdr->daddr);
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = htons(sizeof(iphdr) + sizeof(icmphdr) + 8);
	ip_hdr->protocol = IPPROTO_ICMP;

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
							   sizeof(icmphdr) + 8));
}

void handle_ip_packet(int interface, char *buf, size_t len) {
	cerr << "here\n";
	iphdr *ip_hdr = (iphdr *)(buf + sizeof(ethhdr));

	if (!verify_ip_checksum(ip_hdr)) {
		cerr << "Packet dropped: wrong IP checksum\n";
		return;
	}

	in_addr_t next_ip = ip_hdr->saddr;
	int next_interface = interface;

	if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
		if (ip_hdr->protocol == IPPROTO_ICMP)
			handle_icmp_packet(buf);
		else {
			cerr << "Packet dropped: non-ICMP packet sent to router\n";
			return;
		}			
	} else if (ip_hdr->ttl <= 1) {
		icmp_err(buf, ICMP_TIME_EXCEEDED);
		len = sizeof(ethhdr) + 4 * ip_hdr->ihl + sizeof(icmphdr) + 8;
	}

	optional<pair<in_addr_t, int>> next_hop = find_next_hop(ip_hdr->daddr);

	if (!next_hop.has_value()) {
		icmp_err(buf, ICMP_DEST_UNREACH);
		len = sizeof(ethhdr) + 4 * ip_hdr->ihl + sizeof(icmphdr) + 8;
	} else {
		next_ip = next_hop.value().first;
		next_interface = next_hop.value().second;
	}

	--ip_hdr->ttl;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, 4 * ip_hdr->ihl));

	ethhdr *eth_hdr = (ethhdr *)buf;

	get_interface_mac(interface, eth_hdr->h_source);

	auto it = arp_cache.find(next_ip);

	if (it != arp_cache.end()) {
		memcpy(eth_hdr->h_dest, it->second.begin(), ETH_ALEN);
		send_packet(next_interface, buf, len);
	} else {
		arp_queue[next_ip].push_back(packet(next_interface, buf, len));
		send_arp_request(next_ip, next_interface);
	}
}

void handle_arp_packet(int interface, char *buf, size_t len) {
	arp_header *arp_hdr = (arp_header *)(buf + sizeof(ethhdr));

	if (ntohs(arp_hdr->htype) != ARPHRD_ETHER
		|| ntohs(arp_hdr->ptype) != ETH_P_IP) {
		cerr << "Packet dropped: invalid ARP header\n";
		return;
	}

	if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
		mac tmp;

		memcpy(tmp.begin(), arp_hdr->sha, ETH_ALEN);
		arp_cache[arp_hdr->spa] = tmp;
		
		for (const packet& pkt : arp_queue[arp_hdr->spa]) {
			memcpy(((ethhdr *)pkt.buf)->h_dest, arp_hdr->sha,
				   ETH_ALEN);
			send_packet(pkt.interface, pkt.buf, pkt.len);
			delete[] pkt.buf;
		}

		arp_queue.erase(arp_hdr->spa);
	} else if (ntohs(arp_hdr->op) == ARPOP_REQUEST
			   && arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {
		arp_hdr->op = htons(ARPOP_REPLY);

		// Can't use swap() on packed struct members
		in_addr_t tmp = arp_hdr->tpa;
		arp_hdr->tpa = arp_hdr->spa;
		arp_hdr->spa = tmp;

		memcpy(arp_hdr->tha, arp_hdr->sha, ETH_ALEN);
		get_interface_mac(interface, arp_hdr->sha);

		ethhdr *eth_hdr = (ethhdr *)buf;
		
		memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
		memcpy(eth_hdr->h_source, arp_hdr->sha, ETH_ALEN);

		send_packet(interface, buf, len);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	generate_route_table(argv[1]);

	while (1) {
		size_t len;
		int interface = recv_from_any_link(buf, &len);

		DIE(interface < 0, "recv_from_any_links");

		ethhdr *eth_hdr = (ethhdr *) buf;
		mac interface_mac;
		get_interface_mac(interface, interface_mac.begin());

		if (memcmp(interface_mac.begin(), eth_hdr->h_dest, ETH_ALEN)
			&& memcmp(broadcast_mac.begin(), eth_hdr->h_dest, ETH_ALEN)) {
			cerr << "Packet dropped: wrong destination MAC\n";
			continue;
		}

		switch (ntohs(eth_hdr->h_proto)) {
		case ETH_P_IP:
			handle_ip_packet(interface, buf, len);
			break;
		case ETH_P_ARP:
			handle_arp_packet(interface, buf, len);
			break;
		default:
			cerr << "Packet dropped: unsupported L3 protocol\n";
		}
	}
}