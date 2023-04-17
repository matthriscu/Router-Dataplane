#include <stdint.h>
#include <unistd.h>

/* Ethernet ARP packet from RFC 826 */
struct arp_header {
  uint16_t htype; /* Format of hardware address */
  uint16_t ptype; /* Format of protocol address */
  uint8_t hlen;   /* Length of hardware address */
  uint8_t plen;   /* Length of protocol address */
  uint16_t op;    /* ARP opcode (command) */
  uint8_t sha[6]; /* Sender hardware address */
  uint32_t spa;   /* Sender IP address */
  uint8_t tha[6]; /* Target hardware address */
  uint32_t tpa;   /* Target IP address */
} __attribute__((packed));
