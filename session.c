// {{{ includes

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "session.h"

// }}}

// {{{ time helpers

static int tv_cmp(const struct timeval *a,const struct timeval *b) { // {{{
	if (a->tv_sec!=b->tv_sec)
		return a->tv_sec<b->tv_sec?-1:1;
	if (a->tv_usec!=b->tv_usec)
		return a->tv_usec<b->tv_usec?-1:1;
	return 0;
} // }}}

static struct timeval tv_add_ms(struct timeval t,int ms) { // {{{
	t.tv_sec+=ms/1000;
	t.tv_usec+=(ms%1000)*1000;
	if (t.tv_usec>=1000000) {
		t.tv_sec+=t.tv_usec/1000000;
		t.tv_usec%=1000000;
	}
	return t;
} // }}}

// }}}

// {{{ free helpers

static uint8_t *raw_dup(const uint8_t *src,int len) { // {{{ copy a raw payload, NULL on failure/empty
	uint8_t *p;

	if (!src||len<=0)
		return NULL;
	p=malloc(len);
	if (p)
		memcpy(p,src,len);
	return p;
} // }}}

static void msg_free(struct sess_msg *mm) { // {{{
	free(mm->raw);
	free(mm);
} // }}}

static void tx_free(struct sess_tx *tx) { // {{{
	struct sess_msg *mm=tx->msgs;

	while (mm) {
		struct sess_msg *n=mm->next;

		msg_free(mm);
		mm=n;
	}
	free(tx);
} // }}}

static void sess_free_one(struct sess *s) { // {{{
	struct sess_tx *tx=s->txs;

	while (tx) {
		struct sess_tx *n=tx->next;

		tx_free(tx);
		tx=n;
	}
	free(s);
} // }}}

// }}}

void sess_model_init(struct sess_model *m,int timeout_ms) { // {{{
	m->head=m->tail=NULL;
	m->nsess=0;
	m->now.tv_sec=0;
	m->now.tv_usec=0;
	m->timeout_ms=timeout_ms>0?timeout_ms:SESS_TIMEOUT_MS;
} // }}}

void sess_model_free(struct sess_model *m) { // {{{
	struct sess *s=m->head;

	while (s) {
		struct sess *n=s->next;

		sess_free_one(s);
		s=n;
	}
	m->head=m->tail=NULL;
	m->nsess=0;
} // }}}

static int same_client(const struct sess *s,const struct dhcp_msg *msg) { // {{{ match a client by hardware address
	int n=msg->hlen>16?16:msg->hlen;

	if (n==0) // no hlen given, compare the whole field
		n=16;
	return s->htype==msg->htype&&memcmp(s->chaddr,msg->chaddr,n)==0;
} // }}}

static void sess_unlink(struct sess_model *m,struct sess *s) { // {{{
	if (s->prev)
		s->prev->next=s->next;
	else
		m->head=s->next;
	if (s->next)
		s->next->prev=s->prev;
	else
		m->tail=s->prev;
} // }}}

static void sess_push_tail(struct sess_model *m,struct sess *s) { // {{{ append, keeping a stable first-seen order
	s->next=NULL;
	s->prev=m->tail;
	if (m->tail)
		m->tail->next=s;
	m->tail=s;
	if (!m->head)
		m->head=s;
} // }}}

static void sess_evict_lru(struct sess_model *m) { // {{{ drop the least recently active client without reordering the rest
	struct sess *s,*lru=m->head;

	if (!lru)
		return;
	for (s=m->head->next;s;s=s->next)
		if (tv_cmp(&s->last,&lru->last)<0)
			lru=s;
	sess_unlink(m,lru);
	m->nsess--;
	sess_free_one(lru);
} // }}}

static struct sess *sess_find_or_new(struct sess_model *m,const struct dhcp_msg *msg) { // {{{
	struct sess *s;

	for (s=m->head;s;s=s->next)
		if (same_client(s,msg)) // updated in place, list order stays stable
			return s;

	s=calloc(1,sizeof *s);
	if (!s)
		return NULL;
	memcpy(s->chaddr,msg->chaddr,16);
	s->hlen=msg->hlen;
	s->htype=msg->htype;
	s->first=msg->ts;
	s->last=msg->ts; // so a brand new client is not the LRU pick below
	sess_push_tail(m,s);
	m->nsess++;
	while (m->nsess>SESS_MAX)
		sess_evict_lru(m);
	return s;
} // }}}

static struct sess_tx *tx_find_or_new(struct sess *s,const struct dhcp_msg *msg) { // {{{
	struct sess_tx *tx;

	for (tx=s->txs;tx;tx=tx->next)
		if (tx->xid==msg->xid)
			return tx;

	tx=calloc(1,sizeof *tx);
	if (!tx)
		return NULL;
	tx->xid=msg->xid;
	tx->start=msg->ts;
	tx->prev=NULL; // newest first
	tx->next=s->txs;
	if (s->txs)
		s->txs->prev=tx;
	s->txs=tx;
	if (!s->txs_tail)
		s->txs_tail=tx;
	s->ntx++;
	while (s->ntx>SESS_MAX_TX) { // drop the oldest transaction
		struct sess_tx *old=s->txs_tail;

		if (!old||old==tx)
			break;
		s->txs_tail=old->prev;
		if (old->prev)
			old->prev->next=NULL;
		else
			s->txs=NULL;
		s->ntx--;
		tx_free(old);
	}
	return tx;
} // }}}

static void tx_add_msg(struct sess_tx *tx,const struct dhcp_msg *msg) { // {{{ append oldest first, collapsing retransmissions
	struct sess_msg *mm;

	// a retransmission (same type, direction and server as the last message)
	// bumps a counter instead of piling up identical nodes
	if (tx->msgs_tail&&tx->msgs_tail->msgtype==msg->msgtype
			&&tx->msgs_tail->op==msg->op
			&&tx->msgs_tail->serverid==msg->serverid) {
		tx->msgs_tail->count++;
		tx->msgs_tail->ts=msg->ts;
		free(tx->msgs_tail->raw); // keep the latest retransmission's packet
		tx->msgs_tail->raw=raw_dup(msg->raw,msg->rawlen);
		tx->msgs_tail->rawlen=tx->msgs_tail->raw?msg->rawlen:0;
		return;
	}

	mm=calloc(1,sizeof *mm);
	if (!mm)
		return;
	mm->ts=msg->ts;
	mm->srcip=msg->srcip;
	mm->serverid=msg->serverid;
	mm->msgtype=msg->msgtype;
	mm->op=msg->op;
	mm->count=1;
	mm->raw=raw_dup(msg->raw,msg->rawlen);
	mm->rawlen=mm->raw?msg->rawlen:0;
	if (tx->msgs_tail)
		tx->msgs_tail->next=mm;
	else
		tx->msgs=mm;
	tx->msgs_tail=mm;
	tx->nmsg++;
	while (tx->nmsg>SESS_MAX_MSG) { // drop the oldest message
		struct sess_msg *old=tx->msgs;

		if (!old)
			break;
		tx->msgs=old->next;
		if (tx->msgs_tail==old)
			tx->msgs_tail=NULL;
		msg_free(old);
		tx->nmsg--;
	}
} // }}}

void sess_ingest(struct sess_model *m,const struct dhcp_msg *msg) { // {{{
	struct sess *s;
	struct sess_tx *tx;

	if (tv_cmp(&msg->ts,&m->now)>0) // advance the model clock
		m->now=msg->ts;

	s=sess_find_or_new(m,msg);
	if (!s)
		return;
	s->last=msg->ts;
	s->last_msgtype=msg->msgtype;
	if (msg->hostname[0])
		memcpy(s->hostname,msg->hostname,sizeof s->hostname);
	if (msg->serverid)
		s->server_ip=msg->serverid;
	else if (msg->op==BOOTREPLY&&msg->siaddr)
		s->server_ip=msg->siaddr;

	tx=tx_find_or_new(s,msg);
	if (!tx)
		return;
	tx->last=msg->ts;
	tx_add_msg(tx,msg);

	switch (msg->msgtype) { // advance the request/reply state machine
		case DHCPDISCOVER:
			tx->awaiting=DHCPOFFER;
			tx->deadline=tv_add_ms(msg->ts,m->timeout_ms);
			break;
		case DHCPREQUEST:
			if (msg->serverid) // the client commits to this server
				tx->selected_server=msg->serverid;
			tx->awaiting=DHCPACK;
			tx->deadline=tv_add_ms(msg->ts,m->timeout_ms);
			break;
		case DHCPINFORM:
			tx->awaiting=DHCPACK;
			tx->deadline=tv_add_ms(msg->ts,m->timeout_ms);
			break;
		case DHCPOFFER:
			tx->yiaddr=msg->yiaddr;
			if (tx->awaiting==DHCPOFFER)
				tx->awaiting=0;
			break;
		case DHCPACK:
			tx->yiaddr=msg->yiaddr;
			tx->awaiting=0;
			tx->result=DHCPACK;
			s->lease_ip=msg->yiaddr;
			break;
		case DHCPNAK:
			tx->awaiting=0;
			tx->result=DHCPNAK;
			break;
		case DHCPRELEASE:
		case DHCPDECLINE:
			tx->awaiting=0;
			tx->result=DHCPACK; // terminal, no reply expected
			break;
	}
} // }}}

enum tx_state sess_tx_state(const struct sess_tx *tx,const struct timeval *now) { // {{{
	if (tx->result==DHCPNAK)
		return TX_NAK;
	if (tx->result==DHCPACK)
		return TX_COMPLETE;
	if (tx->awaiting) {
		if (now&&tv_cmp(now,&tx->deadline)>0)
			return TX_TIMEOUT;
		return TX_WAIT;
	}
	return TX_OFFERED;
} // }}}
