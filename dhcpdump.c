// {{{ includes

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

#include "dhcp_options.h"
#include "dhcpdump.h"

// }}}

// {{{ definitions

#define SPERW (7*24*3600)
#define SPERD (24*3600)
#define SPERH (3600)
#define SPERM (60)

#define LARGESTRING 1024

#define DHCP_FIXED 236 // fixed BOOTP header length (op..file), the magic cookie follows

#define OPTVALCOL 44 // column where option values (and their wrapped continuations) sit; matches printHex
#define OPTWRAPCOL 78 // hard wrap column for string values; matches the width of a hex dump line
#define OPTLISTCOL 12 // indent for multi value lists, one item per line under the option header
#define OPTHEXCOL 28 // indent for hex+ascii block values; 28+32 hex digits+1 space puts the ascii at column 61, same as in a hex dump line

// Header geometry, used instead of the layout of struct ether_header/ip/udphdr.
// A captured frame is only byte aligned, so those structs must never be cast
// onto it and dereferenced; every field below is read byte by byte instead.
// Reading the UDP length by offset also sidesteps its member being named len on
// glibc and uh_ulen on the BSDs, so no platform conditional is needed for it.
#define ETH_TYPE_OFF 12 // ethertype, after the two 6 byte addresses
#define ETH_DST_OFF 0 // destination address
#define ETH_SRC_OFF 6 // source address
#define VLAN_TAG_LEN 4 // one 802.1Q/802.1ad tag: 2 bytes TCI after the 2 byte ethertype
#define IP_HDR_MIN 20 // smallest IPv4 header, i.e. IHL 5
#define UDP_HDR_LEN 8 // source, destination, length, checksum
#define UDP_LEN_OFF 4 // the length field within the UDP header

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88a8
#endif

#define strcountof(x) (sizeof(x)/sizeof(*(x)))

// }}}

// Output stream for the option decoder. Set by dhcp_fprint/dhcp_fprint_payload
// before the helpers below run, so the same code renders to stdout (line dump)
// or to a memory stream (TUI packet detail).
static FILE *g_out;

static const uint8_t dhcp_cookie[4]={99,130,83,99}; // RFC 2131 magic cookie, marks the start of the option list

static inline void printIPaddress(const uint8_t *data) { // {{{ print the data as an IP address
	fprintf(g_out,"%u.%u.%u.%u",data[0],data[1],data[2],data[3]);
} // }}}

static inline void printIPaddressAddress(const uint8_t *data) { // {{{ print the data as an IP address and an IP address
	fprintf(g_out,"%u.%u.%u.%u %u.%u.%u.%u",
		data[0],data[1],data[2],data[3],
		data[4],data[5],data[6],data[7]);
} // }}}

static inline void printIPaddressMask(const uint8_t *data) { // {{{ print the data as an IP address and mask
	fprintf(g_out,"%u.%u.%u.%u/%u.%u.%u.%u",
		data[0],data[1],data[2],data[3],
		data[4],data[5],data[6],data[7]);
} // }}}

static inline void print8bits(const uint8_t *data) { // {{{ prints a value of 8 bits (1 byte)
	fprintf(g_out,"%u",data[0]);
} // }}}

static inline void print16bits(const uint8_t *data) { // {{{ prints a value of 16 bits (2 bytes)
	fprintf(g_out,"%u",(unsigned)((data[0]<<8)|data[1]));
} // }}}

static inline void printTimeVal(unsigned t) { // {{{ print a seconds count raw, followed by its w/d/h/m/s breakdown
	unsigned rest=t;
	int any=0;

	fprintf(g_out,"%u (",t);
	if (rest>=SPERW) { // >=, so exactly one week reads 1w and not 7d
		fprintf(g_out,"%uw",rest/(SPERW));
		rest%=SPERW;
		any=1;
	}
	if (rest>=SPERD) {
		fprintf(g_out,"%ud",rest/(SPERD));
		rest%=SPERD;
		any=1;
	}
	if (rest>=SPERH) {
		fprintf(g_out,"%uh",rest/(SPERH));
		rest%=SPERH;
		any=1;
	}
	if (rest>=SPERM) {
		fprintf(g_out,"%um",rest/(SPERM));
		rest%=SPERM;
		any=1;
	}
	if (rest>0||!any) // a zero value still needs one unit printed
		fprintf(g_out,"%us",rest);
	fprintf(g_out,")");
} // }}}

static inline void printTime8(const uint8_t *data) { // {{{ print the data as a 8bits time-value
	printTimeVal(data[0]);
} // }}}

static inline void printTime32(const uint8_t *data) { // {{{ print the data as a 32bits time-value
	// cast before shifting; data[0]<<24 on its own promotes to int and overflows
	printTimeVal(((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|((uint32_t)data[2]<<8)|data[3]);
} // }}}

static inline void printHexBlock(const uint8_t *data,int len) { // {{{ print the data below the option header, 16 bytes per line as condensed hex with the ascii translation aligned to the trailing hex dump
	int i,j;

	for (i=0;i<len;i+=16) {
		fprintf(g_out,"\n%*s",OPTHEXCOL,"");
		for (j=0;j<16;j++) {
			if (i+j<len)
				fprintf(g_out,"%02x",data[i+j]);
			else
				fprintf(g_out,"  ");
		}
		fprintf(g_out," ");
		for (j=0;j<16&&i+j<len;j++) {
			unsigned char c=data[i+j]; // isprint() is undefined for a negative char

			fprintf(g_out,"%c",isprint(c)?c:'.');
		}
	}
} // }}}

static inline int is_printable(const uint8_t *data,int len) { // {{{ true when every byte is printable ascii; a crafted string value may carry terminal escapes, never print one verbatim without this check
	int i;

	for (i=0;i<len;i++)
		if (!isprint(data[i]))
			return 0;
	return 1;
} // }}}

static inline void printWrapped(const uint8_t *data,int len,int firstcol,int contcol,int rmargin) { // {{{ print a value, hard wrapped at an exact column (values are not prose), continuations indented to contcol
	int col=firstcol,i;

	for (i=0;i<len;i++) {
		if (col>=rmargin) {
			fprintf(g_out,"\n%*s",contcol,"");
			col=contcol;
		}
		fprintf(g_out,"%c",data[i]);
		col++;
	}
} // }}}

static inline void printHex(const uint8_t *data,int len) { // {{{ print the data as a hex-list, without the translation into ascii behind it
	int i,j;

	for (i=0;i<=len/8;i++) {
		for (j=0;j<8;j++) {
			if (i*8+j>=len)
				break;
			fprintf(g_out,"%02x",data[i*8+j]);
		}
		if (i*8+j<len)
			fprintf(g_out,"\n%44s","");
	}
} // }}}

static inline void printHexColon(const uint8_t *data,int len) { // {{{ print the data as a hex-list separated by colons
	int i;

	for (i=0;i<len;i++) {
		if (i!=0)
			fprintf(g_out,":");
		fprintf(g_out,"%02x",data[i]);
	}
} // }}}

static inline void printReqParmList(const uint8_t *data,int len) { // {{{ print the list of requested parameters, one per line
	int i;

	for (i=0;i<len;i++)
		fprintf(g_out,"\n%*s%-3d (%s)",OPTLISTCOL,"",data[i],dhcp_options[data[i]]);
} // }}}

static inline void printIPaddressCompactMaskAddress(const uint8_t *data,int len) { // {{{ print the data as series of IP address and masks
	int i,j,isok=1;

	if (len<5)
		isok=0;
	else
		for (i=0;i<len;i++) {
			j=4+(data[i]+7)/8;
			if (data[i]>32||len<i+j+1) {
				isok=0;
				break;
			}
			i+=j;
		}
	if (!isok) {
		fprintf(g_out,"Malformed\n%44s","");
		printHex(data,len);
		return;
	}

	for (i=0;i<len;i++) {
		j=4+(data[i]+7)/8;
		fprintf(g_out,"%s%*s%u.%u.%u.%u/%u via %u.%u.%u.%u",
			i?"\n":"",
			i?44:0,"",
			(unsigned)(j>4?data[i+1]:0),(unsigned)(j>5?data[i+2]:0),
			(unsigned)(j>6?data[i+3]:0),(unsigned)(j>7?data[i+4]:0),data[i],
			data[i+j-3],data[i+j-2],data[i+j-1],data[i+j]);
		i+=j;
	}
} // }}}

static inline int opt_is_str(int o) { // {{{ options whose value is a text string, printed verbatim when fully printable and as a hex+ascii block below the header otherwise
	switch (o) {
		case 12:
		case 14:
		case 15:
		case 17:
		case 18:
		case 40:
		case 56:
		case 62:
		case 64:
		case 66:
		case 67:
		case 86:
		case 87:
		case 100:
		case 101:
		case 114:
		case 147:
			return 1;
	}
	return 0;
} // }}}

static inline int opt_is_inline(int o) { // {{{ options whose value starts on the header line, so the name is padded out to OPTVALCOL; everything else renders below the header and must not be padded (keep in sync with the switch in print_bootp, whose default case is a hex block)
	switch (o) {
		case 1:
		case 2:
		case 13:
		case 16:
		case 19:
		case 20:
		case 22:
		case 23:
		case 24:
		case 26:
		case 27:
		case 28:
		case 29:
		case 30:
		case 31:
		case 32:
		case 34:
		case 35:
		case 36:
		case 37:
		case 38:
		case 39:
		case 46:
		case 50:
		case 51:
		case 52:
		case 53:
		case 54:
		case 57:
		case 58:
		case 59:
		case 63:
		case 81:
		case 91:
		case 93:
		case 94:
		case 108:
		case 116:
		case 118:
		case 121:
		case 145:
		case 152:
		case 153:
		case 154:
		case 155:
		case 211:
		case 249:
			return 1;
	}
	return 0;
} // }}}

static void print_bootp(const uint8_t *data,int data_len) { // {{{ print the BOOTP header and the options (caller ensures data_len>=DHCP_FIXED)
	char buf[LARGESTRING];
	int i,j,valcol,nl;

	fprintf(g_out,"    OP: %d (%s)\n",data[0],data[0]>=strcountof(operands)?"*unknown*":operands[data[0]]);
	fprintf(g_out," HTYPE: %d (%s)\n",data[1],data[1]>=strcountof(htypes)?"*unknown*":htypes[data[1]]);
	fprintf(g_out,"  HLEN: %d\n",data[2]);
	fprintf(g_out,"  HOPS: %d\n",data[3]);
	fprintf(g_out,"   XID: %02x%02x%02x%02x\n",data[4],data[5],data[6],data[7]);
	fprintf(g_out,"  SECS: ");
	print16bits(data+8);
	fprintf(g_out,"\n");
	fprintf(g_out," FLAGS: %x\n",(unsigned)((data[10]<<8)|data[11]));
	fprintf(g_out,"CIADDR: ");
	printIPaddress(data+12);
	fprintf(g_out,"\n");
	fprintf(g_out,"YIADDR: ");
	printIPaddress(data+16);
	fprintf(g_out,"\n");
	fprintf(g_out,"SIADDR: ");
	printIPaddress(data+20);
	fprintf(g_out,"\n");
	fprintf(g_out,"GIADDR: ");
	printIPaddress(data+24);
	fprintf(g_out,"\n");
	fprintf(g_out,"CHADDR: ");
	printHexColon(data+28,16);
	fprintf(g_out,"\n");
	i=(int)strnlen((const char *)(data+44),64); // sname is a fixed 64 byte field, may lack a NUL
	if (is_printable(data+44,i))
		fprintf(g_out," SNAME: %.64s.\n",data+44);
	else {
		fprintf(g_out," SNAME:");
		printHexBlock(data+44,i);
		fprintf(g_out,"\n");
	}
	i=(int)strnlen((const char *)(data+108),128); // file is a fixed 128 byte field, may lack a NUL
	if (is_printable(data+108,i))
		fprintf(g_out," FNAME: %.128s.\n",data+108);
	else {
		fprintf(g_out," FNAME:");
		printHexBlock(data+108,i);
		fprintf(g_out,"\n");
	}

	// Options only follow the RFC 2131 magic cookie. Without it this is plain
	// BOOTP and whatever sits at offset 236 is vendor data, not a TLV list, so
	// decoding it as options would invent plausible looking garbage. Dump the
	// area verbatim instead, it is the only thing left to show.
	if (data_len<DHCP_FIXED+4||memcmp(data+DHCP_FIXED,dhcp_cookie,4)) {
		fprintf(g_out,"VENDOR: *no DHCP magic cookie, plain BOOTP*");
		printHexBlock(data+DHCP_FIXED,data_len-DHCP_FIXED);
		fprintf(g_out,"\n");
		return;
	}
	j=DHCP_FIXED+4;
	while (j<data_len&&data[j]!=255) {
		if (data[j]==0) { // pad option, carries neither a length nor a value byte
			fprintf(g_out,"OPTION: %3d (  0) %s\n",data[j],dhcp_options[data[j]]);
			j++;
			continue;
		}
		if (j+2>data_len||j+2+data[j+1]>data_len) { // length byte and value bytes must be captured
			fprintf(g_out,"OPTION: %3d       *malformed - truncated option*\n",data[j]);
			break;
		}
		nl=(int)strlen(dhcp_options[data[j]]);
		valcol=18+(nl>26?nl:26); // where the value starts (a long name pushes it right)
		// pad the name out to the value column only when a value actually
		// follows on this line, otherwise the padding is trailing whitespace
		if (opt_is_inline(data[j])||(opt_is_str(data[j])&&data[j+1]>0&&is_printable(data+j+2,data[j+1])))
			fprintf(g_out,"OPTION: %3d (%3d) %-26s",data[j],data[j+1],dhcp_options[data[j]]);
		else // value rendered on its own lines below: header carries only the name
			fprintf(g_out,"OPTION: %3d (%3d) %s",data[j],data[j+1],dhcp_options[data[j]]);

		switch (data[j]) {
			default: // no known structure, plus the deliberately opaque ones: 43 vendor specific, 47 NetBIOS scope, 60 class id, 61 client id, 77 user class
				printHexBlock(data+j+2,data[j+1]);
				break;

			case 1: // Subnetmask
			case 16: // Swap server
			case 28: // Broadcast address
			case 32: // Router solicitation
			case 50: // Requested IP address
			case 54: // Server identifier
			case 118: // Subnet selection option
				if (data[j+1]<4)
					fprintf(g_out,"*malformed - too short*");
				else
					printIPaddress(data+j+2);
				break;

			case 12: // Hostname
			case 14: // Merit dump file
			case 15: // Domain name
			case 17: // Root Path
			case 18: // Extensions path
			case 40: // NIS domain
			case 56: // Message
			case 62: // Netware/IP domain name
			case 64: // NIS+ domain
			case 66: // TFTP server name
			case 67: // bootfile name
			case 86: // NDS Tree name
			case 87: // NDS context
			case 100: // PCode - TZ-Posix String
			case 101: // TCode - TX-Database String
			case 114: // Captive-portal
			case 147: // DOTS Reference Identifier
				if (is_printable(data+j+2,data[j+1]))
					printWrapped(data+j+2,data[j+1],valcol,OPTVALCOL,OPTWRAPCOL);
				else
					printHexBlock(data+j+2,data[j+1]);
				break;

			case 3: // Routers
			case 4: // Time servers
			case 5: // Name servers
			case 6: // DNS server
			case 7: // Log server
			case 8: // Cookie server
			case 9: // LPR server
			case 10: // Impress server
			case 11: // Resource location server
			case 41: // NIS servers
			case 42: // NTP servers
			case 44: // NetBIOS name server
			case 45: // NetBIOS datagram distribution server
			case 48: // X Window System font server
			case 49: // X Window System display server
			case 65: // NIS+ servers
			case 68: // Mobile IP home agent
			case 69: // SMTP server
			case 70: // POP3 server
			case 71: // NNTP server
			case 72: // WWW server
			case 73: // Finger server
			case 74: // IRC server
			case 75: // StreetTalk server
			case 76: // StreetTalk directory assistance server
			case 78: // Directory Agent
			case 85: // NDS server
			case 92: // Associated IP
			case 148: // DOTS Address
			case 150: // TFTP server address
			case 162: // Encrypted DNS Server
				for (i=0;i<data[j+1]/4;i++) {
					fprintf(g_out,"\n%*s",OPTLISTCOL,"");
					printIPaddress(data+j+2+i*4);
				}
				break;

			case 21: // Policy filter
				for (i=0;i<data[j+1]/8;i++) {
					fprintf(g_out,"\n%*s",OPTLISTCOL,"");
					printIPaddressMask(data+j+2+i*8);
				}
				break;

			case 33: // Static route
				for (i=0;i<data[j+1]/8;i++) {
					fprintf(g_out,"\n%*s",OPTLISTCOL,"");
					printIPaddressAddress(data+j+2+i*8);
				}
				break;

			case 25: // Path MTU plateau table
				for (i=0;i<data[j+1]/2;i++) {
					fprintf(g_out,"\n%*s",OPTLISTCOL,"");
					print16bits(data+j+2+i*2);
				}
				break;

			case 13: // bootfile size
			case 22: // Maximum datagram reassembly size
			case 26: // Interface MTU
			case 57: // Maximum DHCP message size
				if (data[j+1]<2)
					fprintf(g_out,"*malformed - too short*");
				else
					print16bits(data+j+2);
				break;

			case 19: // IP forwarding enabled/disable
			case 20: // Non-local source routing
			case 27: // All subnets local
			case 29: // Perform mask discovery
			case 30: // Mask supplier
			case 31: // Perform router discovery
			case 34: // Trailer encapsulation
			case 39: // TCP keepalive garbage
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%d (%s)",data[j+2],data[j+2]>=strcountof(enabledisable)?"*unknown*":enabledisable[data[j+2]]);
				break;

			case 23: // Default IP TTL
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					printTime8(data+j+2);
				break;

			case 37: // TCP default TTL
			case 145: // FORCERENEW_NONCE_CAPABLE
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					print8bits(data+j+2);
				break;

			case 46: // NetBIOS over TCP/IP node type
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%d (%s)",data[j+2],data[j+2]>=strcountof(netbios_node_type)?"*unknown*":netbios_node_type[data[j+2]]);
				break;

			case 2: // Time offset
			case 24: // Path MTU aging timeout
			case 35: // ARP cache timeout
			case 38: // TCP keepalive interval
			case 51: // IP address leasetime
			case 58: // T1
			case 59: // T2
			case 91: // Client last transaction time
			case 108: // IPv6-Only preferred
			case 152: // base-time
			case 153: // start-time-of-state
			case 154: // query-start-time
			case 155: // query-end-time
			case 211: // reboot-time
				if (data[j+1]<4)
					fprintf(g_out,"*malformed - too short*");
				else
					printTime32(data+j+2);
				break;

			case 36: // Ethernet encapsulation
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%d (%s)",data[j+2],data[j+2]>=strcountof(ethernet_encapsulation)?"*unknown*":ethernet_encapsulation[data[j+2]]);
				break;

			case 52: // Option overload
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%d (%s)",data[j+2],data[j+2]>=strcountof(option_overload)?"*unknown*":option_overload[data[j+2]]);
				break;

			case 53: // DHCP message type
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%d (%s)",data[j+2],data[j+2]>=strcountof(dhcp_message_types)?"*unknown*":dhcp_message_types[data[j+2]]);
				break;

			case 55: // Parameter Request List
				printReqParmList(data+j+2,data[j+1]);
				break;

			case 63: // Netware/IP domain information
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					printHex(data+j+2,data[j+1]);
				break;

			case 81: // Client FQDN
				if (data[j+1]<3) { // flags + 2 rcode bytes are mandatory
					fprintf(g_out,"*malformed - too short*");
					break;
				}
				print8bits(data+j+2);
				fprintf(g_out,"-");
				print8bits(data+j+3);
				fprintf(g_out,"-");
				print8bits(data+j+4);
				if (data[j+1]==3) // flags and rcodes only, no name follows
					break;
				if (is_printable(data+j+5,data[j+1]-3)) {
					fprintf(g_out," ");
					strncpy(buf,(const char *)&data[j+5],data[j+1]-3);
					buf[data[j+1]-3]=0;
					fprintf(g_out,"%s",buf);
				} else // the E flag makes the name DNS wire format; escapes in a plain name are handled the same way
					printHexBlock(data+j+5,data[j+1]-3);
				break;

			case 82: // Relay Agent Information
				for (i=j+2;i<j+data[j+1]+2;) {
					if (i+2>j+data[j+1]+2) { // suboption code and length bytes must be present
						fprintf(g_out,"\n%-17s *malformed - truncated*"," ");
						break;
					}
					fprintf(g_out,"\n%-17s %s"," ",data[i]>=strcountof(relayagent_suboptions)?"*unknown*":relayagent_suboptions[data[i]]);
					if (i+data[i+1]+2>j+data[j+1]+2) {
						fprintf(g_out," *malformed - too large*\n");
						break;
					}
					printHexBlock(data+i+2,data[i+1]);
					i+=data[i+1]+2;
				}
				break;

			case 93: // Client System Architecture
				if (data[j+1]<2)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%d (%s)",data[j+3],data[j+3]>=strcountof(client_architecture_names)?"*unknown*":client_architecture_names[data[j+3]]);
				break;

			case 94: // Client Network Interface Identifier
				if (data[j+1]<3)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%u (Rev %d.%d)",(unsigned)(data[j+3]<<8|data[j+4]),data[j+3],data[j+4]);
				break;

			case 116: // Auto-Configure
				if (data[j+1]<1)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%d (%s)",data[j+2],data[j+2]>=strcountof(auto_configure)?"*unknown*":auto_configure[data[j+2]]);
				break;

			case 121: // Classless static route
			case 249: // MSFT - Classless route
				printIPaddressCompactMaskAddress(data+j+2,data[j+1]);
				break;

		}
		fprintf(g_out,"\n");

		j+=data[j+1]+2;
	}
} // }}}

void dhcp_hexdump(const uint8_t *buf,int len) { // {{{ full-frame hex dump (the -H output)
	int i;
	char hexb[16*3+2]="";
	char ascb[16+2]="";

	for (i=0;i<len;i++) {
		if (i%16)
			strcat(hexb," ");
		sprintf(hexb+strlen(hexb),"%02x",buf[i]);
		sprintf(ascb+strlen(ascb),"%c",isprint(buf[i])?buf[i]:'.');
		if ((i%16)==15) {
			printf("%s %s\n",hexb,ascb);
			hexb[0]=ascb[0]=0;
		}
	}
	if (strlen(ascb)) {
		printf("%-47s %s\n",hexb,ascb);
	}
} // }}}

static inline unsigned be16(const uint8_t *p) { // {{{ read 2 network order bytes into a host order value, with no alignment requirement
	return ((unsigned)p[0]<<8)|p[1];
} // }}}

int dhcp_decap(const uint8_t *sp,unsigned caplen,struct dhcp_frame *f,FILE *diag) { // {{{ Ethernet/VLAN/IPv4/UDP -> DHCP payload
	unsigned offset=0;
	unsigned etoff; // ethertype under consideration, moves down one VLAN tag at a time
	unsigned ihl;
	unsigned plen;

	f->nvlan=0;

	if (caplen<ETHER_HDR_LEN) {
		if (diag)
			fprintf(diag,"Ignored too short ethernet packet: %u bytes\n",caplen);
		return 0;
	}

	etoff=ETH_TYPE_OFF;

	// Check for IPv4 packets
nexthdr:
	switch (be16(sp+etoff)) {
		case ETH_P_IP:
			offset+=ETHER_HDR_LEN;
			break;
		case ETH_P_8021Q:
		case ETH_P_8021AD:
			if (caplen<ETHER_HDR_LEN+offset+VLAN_TAG_LEN) {
				if (diag)
					fprintf(diag,"Ignored too short ethernet+vlan packet: %u bytes\n",caplen);
				return 0;
			}
			if (f->nvlan>=DHCP_MAX_VLAN) {
				if (diag)
					fprintf(diag,"Ignored too many vlans in packet: %u bytes\n",caplen);
				return 0;
			}
			f->vlan[f->nvlan].type=be16(sp+etoff)==ETH_P_8021Q?'C':'S';
			f->vlan[f->nvlan].id=be16(sp+etoff+2)&0xfff; // TCI: 3 bits priority, 1 bit DEI, 12 bits id
			f->nvlan++;
			offset+=VLAN_TAG_LEN;
			etoff+=VLAN_TAG_LEN;
			goto nexthdr;
		default:
			if (diag) // the innermost ethertype, the one that actually failed to match
				fprintf(diag,"Ignored non IPv4 packet: 0x%x\n",be16(sp+etoff));
			return 0;
	}

	// Check for length
	if (caplen<offset+IP_HDR_MIN) {
		if (diag)
			fprintf(diag,"Ignored too short IPv4 packet: %u bytes\n",caplen);
		return 0;
	}

	// The version, protocol and fragment offset are checked here rather than
	// left to the caller's capture filter, so the contract of this function
	// holds for any caller: it returns 1 only for unfragmented UDP over IPv4.
	if ((sp[offset]>>4)!=4) { // version is the high nibble of the first byte
		if (diag)
			fprintf(diag,"Ignored non IPv4 packet: version %u\n",sp[offset]>>4);
		return 0;
	}
	if (sp[offset+9]!=IPPROTO_UDP) {
		if (diag)
			fprintf(diag,"Ignored non UDP packet: protocol %u\n",sp[offset+9]);
		return 0;
	}
	if (((sp[offset+6]&0x1f)|sp[offset+7])!=0) { // non zero fragment offset: no UDP header here
		if (diag)
			fprintf(diag,"Ignored IPv4 fragment: offset %u\n",(unsigned)(((sp[offset+6]&0x1f)<<8)|sp[offset+7])*8);
		return 0;
	}
	ihl=sp[offset]&0x0f; // IHL is the low nibble of the first byte
	if (ihl<5)
		ihl=5;
	memcpy(&f->srcip,sp+offset+12,4); // src/dst addresses stay in network order
	memcpy(&f->dstip,sp+offset+16,4);
	offset+=ihl*4;

	if (caplen<offset+UDP_HDR_LEN) {
		if (diag)
			fprintf(diag,"Ignored too short UDP packet: %u bytes\n",caplen);
		return 0;
	}

	// Length of the DHCP payload: trust neither the UDP length field nor the
	// capture length on its own, use whichever is smaller. The UDP length
	// counts its own 8 byte header, the captured payload starts after it.
	plen=be16(sp+offset+UDP_LEN_OFF);
	offset+=UDP_HDR_LEN;
	if (plen<UDP_HDR_LEN)
		plen=0;
	else
		plen-=UDP_HDR_LEN;
	if (plen>caplen-offset)
		plen=caplen-offset;

	memcpy(f->smac,sp+ETH_SRC_OFF,6);
	memcpy(f->dmac,sp+ETH_DST_OFF,6);
	f->payload=sp+offset;
	f->plen=plen;

	return 1;
} // }}}

void dhcp_fprint(FILE *out,const struct dhcp_frame *f,const char *ts) { // {{{ verbose dump of a decapsulated frame to out
	char sip[40],dip[40],smac[40],dmac[40];
	int i;

	g_out=out;

	if (f->nvlan)
		fprintf(g_out,"  VLAN:");
	for (i=0;i<f->nvlan;i++)
		fprintf(g_out," %c:%04u",f->vlan[i].type,f->vlan[i].id);
	if (f->nvlan)
		fprintf(g_out,"\n");

	if (f->plen==0)
		return;
	if (f->plen<DHCP_FIXED) { // the fixed BOOTP header (op..file) must be present
		fprintf(stderr,"Ignored too short DHCP packet: %d bytes\n",f->plen);
		return;
	}

	inet_ntop(AF_INET,&f->srcip,sip,sizeof sip);
	inet_ntop(AF_INET,&f->dstip,dip,sizeof dip);
	snprintf(smac,sizeof smac,"%02x:%02x:%02x:%02x:%02x:%02x",
		f->smac[0],f->smac[1],f->smac[2],f->smac[3],f->smac[4],f->smac[5]);
	snprintf(dmac,sizeof dmac,"%02x:%02x:%02x:%02x:%02x:%02x",
		f->dmac[0],f->dmac[1],f->dmac[2],f->dmac[3],f->dmac[4],f->dmac[5]);

	fprintf(g_out,"  TIME: %s\n",ts);
	fprintf(g_out,"    IP: %s (%s) > %s (%s)\n",sip,smac,dip,dmac);
	print_bootp(f->payload,f->plen);
	fprintf(g_out,"--------------------------------------------------------------------------------\n\n");
	fflush(g_out);
} // }}}

void dhcp_print(const struct dhcp_frame *f,const char *ts) { // {{{ classic verbose dump to stdout
	dhcp_fprint(stdout,f,ts);
} // }}}

static void hexdump_c(const uint8_t *data,int len,const char *bar) { // {{{ hexdump -C style dump to g_out; bar is the vertical separator glyph
	int i,j;

	// like hexdump -C, but the trailing bar is also space padded on the last
	// partial line so both bars line up vertically across every row
	for (i=0;i<len;i+=16) {
		fprintf(g_out,"%08x ",(unsigned)i);
		for (j=0;j<16;j++) {
			if (j%8==0)
				fprintf(g_out," ");
			if (i+j<len)
				fprintf(g_out,"%02x ",data[i+j]);
			else
				fprintf(g_out,"   ");
		}
		fprintf(g_out," %s",bar);
		for (j=0;j<16;j++) {
			if (i+j<len) {
				unsigned char c=data[i+j];

				fprintf(g_out,"%c",isprint(c)?c:'.');
			} else
				fprintf(g_out," ");
		}
		fprintf(g_out,"%s\n",bar);
	}
} // }}}

void dhcp_fprint_payload(FILE *out,const uint8_t *data,int data_len,const char *bar) { // {{{ decode + hex dump of a DHCP payload (TUI packet detail)
	g_out=out;
	if (data_len<DHCP_FIXED) {
		fprintf(g_out,"*truncated - %d bytes*\n",data_len);
		return;
	}
	print_bootp(data,data_len);
	fprintf(g_out,"\n");
	hexdump_c(data,data_len,bar?bar:"|");
} // }}}
