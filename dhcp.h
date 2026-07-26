// {{{ header

#ifndef ___DHCPDUMP_DHCP_H___
#define ___DHCPDUMP_DHCP_H___

#include <stdint.h>
#include <sys/time.h>

// }}}

// Structured DHCP field extraction, part of libdhcpdump. Where dhcp_print gives
// a human readable dump, dhcp_parse pulls the few fields the session tracker
// needs into a struct. IPv4 addresses are kept host order (b0<<24|...|b3) for
// easy formatting as (x>>24).(x>>16&255).(x>>8&255).(x&255).

// {{{ DHCP message types (option 53)

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

// }}}

// {{{ BOOTP op field

#define BOOTREQUEST 1 // client -> server
#define BOOTREPLY 2 // server -> client

// }}}

// {{{ parsed message

struct dhcp_msg {
	struct timeval ts; // capture time; set by the caller, not by dhcp_parse
	uint32_t srcip; // L3 source, host order; set by the caller
	uint32_t dstip; // L3 destination, host order; set by the caller
	uint8_t op; // BOOTREQUEST / BOOTREPLY
	uint8_t htype; // hardware type
	uint8_t hlen; // hardware address length (clamped to <=16)
	uint32_t xid; // transaction id, host order
	uint8_t chaddr[16]; // client hardware address (hlen bytes significant)
	uint32_t ciaddr; // client IP
	uint32_t yiaddr; // your (assigned) IP
	uint32_t siaddr; // next server IP
	uint32_t giaddr; // relay agent IP
	uint8_t msgtype; // option 53, 0 if absent
	uint32_t serverid; // option 54, 0 if absent
	char hostname[64]; // option 12, empty if absent
};

// }}}

// {{{ api

// Extract the DHCP fields from a UDP payload (data,data_len) into out. Only the
// packet-derived fields are set; the caller fills ts/srcip/dstip. Returns 1 if
// this is a usable DHCP message (fixed header present), 0 otherwise.
int dhcp_parse(const uint8_t *data,int data_len,struct dhcp_msg *out);

// Name of a DHCP message type (option 53 value), never NULL.
const char *dhcp_msgtype_name(uint8_t msgtype);

// }}}

#endif
