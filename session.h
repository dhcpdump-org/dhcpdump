// {{{ header

#ifndef ___DHCPDUMP_SESSION_H___
#define ___DHCPDUMP_SESSION_H___

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>

#include "dhcp.h"

// }}}

// DHCP session tracker. A session is one client, keyed by its hardware address;
// within it, transactions are grouped by XID, and each transaction keeps the
// ordered messages it saw plus a derived state (waiting / offered / bound /
// NAK / declined / timed-out). Storage is bounded so a long lived live capture cannot grow
// without limit. The tracker keeps no global state; all of it hangs off one
// struct sess_model, so it can be embedded in either the CLI or the TUI.

// {{{ tuning

#define SESS_MAX 1024 // max tracked clients (LRU eviction beyond this)
#define SESS_MAX_TX 16 // max transactions kept per client
#define SESS_MAX_MSG 32 // max messages kept per transaction
#define SESS_TIMEOUT_MS 5000 // default: a request unanswered this long is timed out

// }}}

// {{{ derived transaction state

enum tx_state {
	TX_WAIT, // a request was sent, its reply is still due (within deadline)
	TX_OFFERED, // an offer was seen, waiting for the client to proceed
	TX_COMPLETE, // concluded, e.g. ACK/bound or RELEASE
	TX_NAK, // server refused with NAK
	TX_DECLINED, // client refused the address with DECLINE (e.g. found it in use)
	TX_TIMEOUT, // a due reply never arrived before the deadline
};

// awaiting value for a plain BOOTP request: a reply is due, but BOOTP has no
// message type option to name it - any BOOTREPLY in the transaction concludes it
#define SESS_AWAIT_ANY 0xff

// }}}

// {{{ model

struct sess_msg { // one message inside a transaction, oldest first
	struct timeval ts; // time of the most recent (retransmitted) copy
	uint8_t *raw; // kept copy of the DHCP payload (for the full packet view), or NULL
	int rawlen; // length of raw
	uint32_t srcip; // host order, sender L3 address
	uint32_t serverid; // server identifier (option 54), 0 if none
	uint32_t reqip; // requested IP (option 50), host order, 0 if none
	uint32_t yiaddr; // offered/assigned IP (BOOTREPLY), host order, 0 if none
	uint32_t ciaddr; // client's own IP (e.g. renewing), host order, 0 if none
	struct dhcp_vlan vlan[DHCP_MAX_VLAN]; // VLAN tags of the frame (latest copy)
	int nvlan; // number of tags in vlan[], 0 when untagged
	uint8_t msgtype; // DHCP message type (option 53)
	uint8_t op; // BOOTREQUEST / BOOTREPLY (direction)
	int count; // identical messages collapsed here (retransmissions), >=1
	struct sess_msg *next;
};

struct sess_tx { // one transaction (a single XID), newest first within a session
	uint32_t xid;
	struct timeval start; // first message time
	struct timeval last; // most recent message time
	struct timeval deadline; // when the pending reply times out (valid if awaiting)
	uint8_t awaiting; // reply msgtype still due (SESS_AWAIT_ANY for plain BOOTP), 0 if none
	uint8_t result; // 0 in progress, DHCPACK bound/concluded, DHCPNAK refused, DHCPDECLINE declined
	uint32_t yiaddr; // offered/assigned IP, host order
	uint32_t selected_server; // server the client accepted (REQUEST option 54)
	struct sess_msg *msgs,*msgs_tail; // messages, oldest first
	int nmsg;
	struct sess_tx *prev,*next;
};

struct sess { // one client, keyed by hardware address; kept in stable first-seen order
	uint8_t chaddr[16];
	uint8_t hlen;
	uint8_t htype;
	struct dhcp_vlan vlan[DHCP_MAX_VLAN]; // VLAN tags of the latest frame
	int nvlan; // number of tags in vlan[], 0 when untagged
	struct timeval first,last;
	uint32_t lease_ip; // last assigned IP (from ACK), host order
	uint32_t server_ip; // last server seen (option 54 / siaddr), host order
	char hostname[64];
	struct sess_tx *txs,*txs_tail; // transactions, newest first
	int ntx;
	struct sess *prev,*next;
};

struct sess_model {
	struct sess *head,*tail; // clients, in first-seen order (stable, no reshuffling)
	int nsess;
	struct timeval now; // model clock: latest packet time seen
	int timeout_ms; // reply timeout
	// Called just before a message node is freed. Storage is bounded, so
	// ingesting a packet can evict messages a viewer is still pointing at;
	// the hook lets it drop the pointer instead of holding a dangling one.
	void (*on_msg_free)(const struct sess_msg *mm,void *user);
	void *on_msg_free_user;
};

// }}}

// {{{ api

void sess_model_init(struct sess_model *m,int timeout_ms);
void sess_model_free(struct sess_model *m);

// Register the message eviction hook (see on_msg_free above); cb may be NULL.
void sess_model_on_msg_free(struct sess_model *m,void (*cb)(const struct sess_msg *,void *),void *user);

// Feed one parsed message into the model, creating/updating client+transaction.
void sess_ingest(struct sess_model *m,const struct dhcp_msg *msg);

// Derived display state of a transaction as of time now.
enum tx_state sess_tx_state(const struct sess_tx *tx,const struct timeval *now);

// }}}

#endif
