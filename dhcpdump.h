// {{{ header

#ifndef ___DHCPDUMP_H___
#define ___DHCPDUMP_H___

#include <stdio.h>
#include <stdint.h>

// }}}

// libdhcpdump - DHCP packet parsing and rendering
//
// The library turns a captured Ethernet frame into a DHCP payload
// (dhcp_decap) and renders it in the classic dhcpdump text form (dhcp_print).
// It keeps no global state and does no I/O of its own except the printing
// calls, so it can be reused by both the line-dump CLI and the TUI.

#define DHCP_MAX_VLAN 2 // max stacked VLAN tags decoded (untagged, 802.1Q, QinQ)

// {{{ decapsulated frame

struct dhcp_vlan { // one stacked VLAN tag
	char type; // 'C' for 802.1Q, 'S' for 802.1ad
	uint16_t id; // 12 bit VLAN id
};

struct dhcp_frame { // result of decapsulating a captured Ethernet frame
	const uint8_t *payload; // DHCP payload, points into the caller's buffer
	int plen; // payload length, already bounded to the captured bytes
	uint32_t srcip; // IPv4 source, network byte order
	uint32_t dstip; // IPv4 destination, network byte order
	uint8_t smac[6]; // source MAC
	uint8_t dmac[6]; // destination MAC
	struct dhcp_vlan vlan[DHCP_MAX_VLAN];
	int nvlan; // number of VLAN tags in vlan[]
};

// }}}

// {{{ api

// Decapsulate a captured Ethernet frame (frame,caplen) into f. Returns 1 if it
// is a DHCP-over-UDP/IPv4 frame and f is filled, 0 otherwise. If diag is
// non-NULL, the reason a frame is ignored is written there (e.g. stderr).
int dhcp_decap(const uint8_t *frame,unsigned caplen,struct dhcp_frame *f,FILE *diag);

// Classic verbose dump of a decapsulated frame to stdout; ts is a preformatted
// timestamp string shown on the TIME: line.
void dhcp_print(const struct dhcp_frame *f,const char *ts);

// Same, but to an arbitrary stream (e.g. a memory stream for the TUI).
void dhcp_fprint(FILE *out,const struct dhcp_frame *f,const char *ts);

// Decode just the BOOTP header and options of a DHCP payload to out, without
// the VLAN/TIME/IP frame lines. Used to render a stored packet in the TUI.
void dhcp_fprint_payload(FILE *out,const uint8_t *data,int data_len,const char *bar);

// Full-frame hex dump (the -H output) to stdout.
void dhcp_hexdump(const uint8_t *buf,int len);

// }}}

#endif
