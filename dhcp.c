// {{{ includes

#include <ctype.h>
#include <string.h>
#include <stdint.h>

#include "dhcp.h"

// }}}

// {{{ definitions

#define DHCP_FIXED 236 // fixed BOOTP header length (op..file), before the cookie

// }}}

static const uint8_t dhcp_cookie[4]={99,130,83,99}; // RFC 2131 magic cookie, marks the start of the option list

static const char *msgtype_names[]={ // {{{ option 53 values
	/*  0 */ "undefined",
	/*  1 */ "DISCOVER",
	/*  2 */ "OFFER",
	/*  3 */ "REQUEST",
	/*  4 */ "DECLINE",
	/*  5 */ "ACK",
	/*  6 */ "NAK",
	/*  7 */ "RELEASE",
	/*  8 */ "INFORM",
	/*  9 */ "FORCERENEW",
	/* 10 */ "LEASEQUERY",
	/* 11 */ "LEASEUNASSIGNED",
	/* 12 */ "LEASEUNKNOWN",
	/* 13 */ "LEASEACTIVE",
	/* 14 */ "BULKLEASEQUERY",
	/* 15 */ "LEASEQUERYDONE",
	/* 16 */ "ACTIVELEASEQUERY",
	/* 17 */ "LEASEQUERYSTATUS",
	/* 18 */ "TLS",
}; // }}}

const char *dhcp_msgtype_name(uint8_t msgtype) { // {{{
	if (msgtype>=sizeof msgtype_names/sizeof *msgtype_names)
		return "*unknown*";
	return msgtype_names[msgtype];
} // }}}

static inline uint32_t be32(const uint8_t *p) { // {{{ read 4 bytes big-endian into a host order value
	return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
} // }}}

int dhcp_parse(const uint8_t *data,int data_len,struct dhcp_msg *out) { // {{{ extract the fields the tracker needs
	int j;

	if (data_len<DHCP_FIXED) // the fixed BOOTP header must be present
		return 0;

	memset(out,0,sizeof *out);

	out->op=data[0];
	out->htype=data[1];
	out->hlen=data[2]>16?16:data[2]; // chaddr is a fixed 16 byte field
	out->xid=be32(data+4);
	out->ciaddr=be32(data+12);
	out->yiaddr=be32(data+16);
	out->siaddr=be32(data+20);
	out->giaddr=be32(data+24);
	memcpy(out->chaddr,data+28,16);

	// Options start after the magic cookie at offset 236. Without it this is
	// plain BOOTP and the bytes there are vendor data, not a TLV list; the
	// fixed header is still usable, so report success with no options parsed.
	if (data_len<DHCP_FIXED+4||memcmp(data+DHCP_FIXED,dhcp_cookie,4))
		return 1;
	j=DHCP_FIXED+4;
	while (j<data_len&&data[j]!=255) {
		if (data[j]==0) { // pad option, no length or value byte
			j++;
			continue;
		}
		if (j+2>data_len||j+2+data[j+1]>data_len) // length byte and value must be present
			break;

		switch (data[j]) {
			case 53: // DHCP message type
				if (data[j+1]>=1)
					out->msgtype=data[j+2];
				break;
			case 54: // server identifier
				if (data[j+1]>=4)
					out->serverid=be32(data+j+2);
				break;
			case 50: // requested IP address
				if (data[j+1]>=4)
					out->reqip=be32(data+j+2);
				break;
			case 12: { // hostname
				int n=data[j+1],i;

				if (n>(int)sizeof out->hostname-1)
					n=sizeof out->hostname-1;
				memcpy(out->hostname,data+j+2,n);
				out->hostname[n]=0;
				for (i=0;i<n;i++) { // a crafted hostname may carry terminal escapes, the TUI prints this verbatim
					unsigned char c=out->hostname[i]; // isprint() is undefined for a negative char

					if (!isprint(c))
						out->hostname[i]='.';
				}
				break;
			}
		}

		j+=data[j+1]+2;
	}

	return 1;
} // }}}
