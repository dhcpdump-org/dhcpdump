// {{{ includes

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/if_arp.h>
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

#ifdef __linux__
#define UDP_LEN_F len
#else
#define UDP_LEN_F uh_ulen
#endif

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

static inline void printIPaddress(const uint8_t *data) { // {{{ print the data as an IP address
	printf("%u.%u.%u.%u",data[0],data[1],data[2],data[3]);
} // }}}

static inline void printIPaddressAddress(const uint8_t *data) { // {{{ print the data as an IP address and an IP address
	printf("%u.%u.%u.%u %u.%u.%u.%u",
		data[0],data[1],data[2],data[3],
		data[4],data[5],data[6],data[7]);
} // }}}

static inline void printIPaddressMask(const uint8_t *data) { // {{{ print the data as an IP address and mask
	printf("%u.%u.%u.%u/%u.%u.%u.%u",
		data[0],data[1],data[2],data[3],
		data[4],data[5],data[6],data[7]);
} // }}}

static inline void print8bits(const uint8_t *data) { // {{{ prints a value of 8 bits (1 byte)
	printf("%u",data[0]);
} // }}}

static inline void print16bits(const uint8_t *data) { // {{{ prints a value of 16 bits (2 bytes)
	printf("%u",(data[0]<<8)|data[1]);
} // }}}

static inline void printTime8(const uint8_t *data) { // {{{ print the data as a 8bits time-value
	unsigned t=data[0];

	printf("%u (",t);
	if (t>SPERW) {
		printf("%uw",t/(SPERW));
		t%=SPERW;
	}
	if (t>SPERD) {
		printf("%ud",t/(SPERD));
		t%=SPERD;
	}
	if (t>SPERH) {
		printf("%uh",t/(SPERH));
		t%=SPERH;
	}
	if (t>SPERM) {
		printf("%um",t/(SPERM));
		t%=SPERM;
	}
	if (t>0)
		printf("%us",t);
	printf(")");
} // }}}

static inline void printTime32(const uint8_t *data) { // {{{ print the data as a 32bits time-value
	unsigned t=(data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3];

	printf("%u (",t);
	if (t>SPERW) {
		printf("%uw",t/(SPERW));
		t%=SPERW;
	}
	if (t>SPERD) {
		printf("%ud",t/(SPERD));
		t%=SPERD;
	}
	if (t>SPERH) {
		printf("%uh",t/(SPERH));
		t%=SPERH;
	}
	if (t>SPERM) {
		printf("%um",t/(SPERM));
		t%=SPERM;
	}
	if (t>0)
		printf("%us",t);
	printf(")");
} // }}}

static inline void printHexString(const uint8_t *data,int len,int clen) { // {{{ print the data as a hex-list, with the translation into ascii behind it
	int i,j,k;

	for (i=0;i<=len/clen;i++) {
		for (j=0;j<clen;j++) {
			if (i*clen+j>=len)
				break;
			printf("%02x",data[i*clen+j]);
		}
		for (k=j;k<clen;k++)
			printf("  ");
		printf(" ");
		for (j=0;j<clen;j++) {
			unsigned char c=data[i*clen+j]; // isprint() is undefined for a negative char

			if (i*clen+j>=len)
				break;
			printf("%c",isprint(c)?c:'.');
		}
		if (i*clen+j<len)
			printf("\n%44s","");
	}
} // }}}

static inline void printHex(const uint8_t *data,int len) { // {{{ print the data as a hex-list, without the translation into ascii behind it
	int i,j;

	for (i=0;i<=len/8;i++) {
		for (j=0;j<8;j++) {
			if (i*8+j>=len)
				break;
			printf("%02x",data[i*8+j]);
		}
		if (i*8+j<len)
			printf("\n%44s","");
	}
} // }}}

static inline void printHexColon(const uint8_t *data,int len) { // {{{ print the data as a hex-list separated by colons
	int i;

	for (i=0;i<len;i++) {
		if (i!=0)
			printf(":");
		printf("%02x",data[i]);
	}
} // }}}

static inline void printReqParmList(const uint8_t *data,int len) { // {{{ print the list of requested parameters
	int i;

	for (i=0;i<len;i++)
		printf("%-3d (%s)%s%*s",data[i],dhcp_options[data[i]],(i+1<len)?"\n":"",(i+1<len)?44:0,"");
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
		printf("Malformed\n%44s","");
		printHex(data,len);
		return;
	}

	for (i=0;i<len;i++) {
		j=4+(data[i]+7)/8;
		printf("%s%*s%u.%u.%u.%u/%u via %u.%u.%u.%u",
			i?"\n":"",
			i?44:0,"",
			j>4?data[i+1]:0,j>5?data[i+2]:0,j>6?data[i+3]:0,j>7?data[i+4]:0,data[i],
			data[i+j-3],data[i+j-2],data[i+j-1],data[i+j]);
		i+=j;
	}
} // }}}

static void print_payload(const uint8_t *data,int data_len,const char *ts,const char *sip,const char *smac,const char *dip,const char *dmac) { // {{{ print the header and the options
	char buf[LARGESTRING];
	int i,j;

	if (data_len==0)
		return;

	if (data_len<236) { // the fixed BOOTP header (op..file) is 236 bytes
		fprintf(stderr,"Ignored too short DHCP packet: %d bytes\n",data_len);
		return;
	}

	printf("  TIME: %s\n",ts);
	printf("    IP: %s (%s) > %s (%s)\n",sip,smac,dip,dmac);
	printf("    OP: %d (%s)\n",data[0],data[0]>=strcountof(operands)?"*unknown*":operands[data[0]]);
	printf(" HTYPE: %d (%s)\n",data[1],data[1]>=strcountof(htypes)?"*unknown*":htypes[data[1]]);
	printf("  HLEN: %d\n",data[2]);
	printf("  HOPS: %d\n",data[3]);
	printf("   XID: %02x%02x%02x%02x\n",data[4],data[5],data[6],data[7]);
	printf("  SECS: ");
	print16bits(data+8);
	printf("\n");
	printf(" FLAGS: %x\n",(data[10]<<8)|data[11]);
	printf("CIADDR: ");
	printIPaddress(data+12);
	printf("\n");
	printf("YIADDR: ");
	printIPaddress(data+16);
	printf("\n");
	printf("SIADDR: ");
	printIPaddress(data+20);
	printf("\n");
	printf("GIADDR: ");
	printIPaddress(data+24);
	printf("\n");
	printf("CHADDR: ");
	printHexColon(data+28,16);
	printf("\n");
	printf(" SNAME: %.64s.\n",data+44); // sname is a fixed 64 byte field, may lack a NUL
	printf(" FNAME: %.128s.\n",data+108); // file is a fixed 128 byte field, may lack a NUL

	j=236;
	j+=4; // cookie
	while (j<data_len&&data[j]!=255) {
		if (data[j]==0) { // pad option, carries neither a length nor a value byte
			printf("OPTION: %3d (  0) %-26s\n",data[j],dhcp_options[data[j]]);
			j++;
			continue;
		}
		if (j+2>data_len||j+2+data[j+1]>data_len) { // length byte and value bytes must be captured
			printf("OPTION: %3d       *malformed - truncated option*\n",data[j]);
			break;
		}
		printf("OPTION: %3d (%3d) %-26s",data[j],data[j+1],dhcp_options[data[j]]);

		switch (data[j]) {
			default:
				printHexString(data+j+2,data[j+1],8);
				break;

			case 1: // Subnetmask
			case 16: // Swap server
			case 28: // Broadcast address
			case 32: // Router solicitation
			case 50: // Requested IP address
			case 54: // Server identifier
			case 118: // Subnet selection option
				if (data[j+1]<4)
					printf("*malformed - too short*");
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
				strncpy(buf,(char *)&data[j+2],data[j+1]);
				buf[data[j+1]]=0;
				printf("%s",buf);
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
					if (i!=0)
						printf(",");
					printIPaddress(data+j+2+i*4);
				}
				break;

			case 21: // Policy filter
				for (i=0;i<data[j+1]/8;i++) {
					if (i!=0)
						printf(",");
					printIPaddressMask(data+j+2+i*8);
				}
				break;

			case 33: // Static route
				for (i=0;i<data[j+1]/8;i++) {
					if (i!=0)
						printf(",");
					printIPaddressAddress(data+j+2+i*8);
				}
				break;

			case 25: // Path MTU plateau table
				for (i=0;i<data[j+1]/2;i++) {
					if (i!=0)
						printf(",");
					print16bits(data+j+2+i*2);
				}
				break;

			case 13: // bootfile size
			case 22: // Maximum datagram reassembly size
			case 26: // Interface MTU
			case 57: // Maximum DHCP message size
				if (data[j+1]<2)
					printf("*malformed - too short*");
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
					printf("*malformed - too short*");
				else
					printf("%d (%s)",data[j+2],data[j+2]>=strcountof(enabledisable)?"*unknown*":enabledisable[data[j+2]]);
				break;

			case 23: // Default IP TTL
				if (data[j+1]<1)
					printf("*malformed - too short*");
				else
					printTime8(data+j+2);
				break;

			case 37: // TCP default TTL
			case 145: // FORCERENEW_NONCE_CAPABLE
				if (data[j+1]<1)
					printf("*malformed - too short*");
				else
					print8bits(data+j+2);
				break;

			case 43: // Vendor specific info
			case 47: // NetBIOS scope (no idea how it looks like)
				printHexString(data+j+2,data[j+1],8);
				break;

			case 46: // NetBIOS over TCP/IP node type
				if (data[j+1]<1)
					printf("*malformed - too short*");
				else
					printf("%d (%s)",data[j+2],data[j+2]>=strcountof(netbios_node_type)?"*unknown*":netbios_node_type[data[j+2]]);
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
					printf("*malformed - too short*");
				else
					printTime32(data+j+2);
				break;

			case 36: // Ethernet encapsulation
				if (data[j+1]<1)
					printf("*malformed - too short*");
				else
					printf("%d (%s)",data[j+2],data[j+2]>=strcountof(ethernet_encapsulation)?"*unknown*":ethernet_encapsulation[data[j+2]]);
				break;

			case 52: // Option overload
				if (data[j+1]<1)
					printf("*malformed - too short*");
				else
					printf("%d (%s)",data[j+2],data[j+2]>=strcountof(option_overload)?"*unknown*":option_overload[data[j+2]]);
				break;

			case 53: // DHCP message type
				if (data[j+1]<1)
					printf("*malformed - too short*");
				else
					printf("%d (%s)",data[j+2],data[j+2]>=strcountof(dhcp_message_types)?"*unknown*":dhcp_message_types[data[j+2]]);
				break;

			case 55: // Parameter Request List
				printReqParmList(data+j+2,data[j+1]);
				break;

			case 63: // Netware/IP domain information
				printHex(data+j+2,data[j+1]);
				break;

			case 60: // Class identifier
			case 61: // Client identifier
			case 77: // User class
				printHexString(data+j+2,data[j+1],8);
				break;

			case 81: // Client FQDN
				if (data[j+1]<3) { // flags + 2 rcode bytes are mandatory
					printf("*malformed - too short*");
					break;
				}
				print8bits(data+j+2);
				printf("-");
				print8bits(data+j+3);
				printf("-");
				print8bits(data+j+4);
				printf(" ");
				strncpy(buf,(char *)&data[j+5],data[j+1]-3);
				buf[data[j+1]-3]=0;
				printf("%s",buf);
				break;

			case 82: // Relay Agent Information
				for (i=j+2;i<j+data[j+1]+2;) {
					if (i+2>j+data[j+1]+2) { // suboption code and length bytes must be present
						printf("\n%-17s *malformed - truncated*"," ");
						break;
					}
					printf("\n%-17s %-10s "," ",data[i]>=strcountof(relayagent_suboptions)?"*unknown*":relayagent_suboptions[data[i]]);
					if (i+data[i+1]+2>j+data[j+1]+2) {
						printf("*malformed - too large*\n");
						break;
					}
					printHexString(data+i+2,data[i+1],16);
					i+=data[i+1]+2;
				}
				break;

			case 93: // Client System Architecture
				if (data[j+1]<2)
					printf("*malformed - too short*");
				else
					printf("%d (%s)",data[j+3],data[j+3]>=strcountof(client_architecture_names)?"*unknown*":client_architecture_names[data[j+3]]);
				break;

			case 94: // Client Network Interface Identifier
				if (data[j+1]<3)
					printf("*malformed - too short*");
				else
					printf("%u (Rev %d.%d)",(data[j+3]<<8|data[j+4]),data[j+3],data[j+4]);
				break;

			case 116: // Auto-Configure
				if (data[j+1]<1)
					printf("*malformed - too short*");
				else
					printf("%d (%s)",data[j+2],data[j+2]>=strcountof(auto_configure)?"*unknown*":auto_configure[data[j+2]]);
				break;

			case 121: // Classless static route
			case 249: // MSFT - Classless route
				printIPaddressCompactMaskAddress(data+j+2,data[j+1]);
				break;

		}
		printf("\n");

		j+=data[j+1]+2;
	}

	printf("--------------------------------------------------------------------------------\n\n");
	fflush(stdout);
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

int dhcp_decap(const uint8_t *sp,unsigned caplen,struct dhcp_frame *f,FILE *diag) { // {{{ Ethernet/VLAN/IPv4/UDP -> DHCP payload
	const struct ether_header *eh;
	const struct udphdr *udp;
	const uint16_t *et;
	unsigned offset=0;
	const struct ip *ip;
	unsigned ihl;
	unsigned plen;

	f->nvlan=0;

	if (caplen<ETHER_HDR_LEN) {
		if (diag)
			fprintf(diag,"Ignored too short ethernet packet: %d bytes\n",caplen);
		return 0;
	}

	eh=(const struct ether_header *)(sp+offset);
	et=(const uint16_t *)(sp+offset+sizeof *eh);
	et--;

	// Check for IPv4 packets
nexthdr:
	switch (ntohs(*et)) {
		case ETH_P_IP:
			offset+=ETHER_HDR_LEN;
			break;
		case ETH_P_8021Q:
		case ETH_P_8021AD:
			if (caplen<ETHER_HDR_LEN+offset+4) {
				if (diag)
					fprintf(diag,"Ignored too short ethernet+vlan packet: %d bytes\n",caplen);
				return 0;
			}
			if (f->nvlan>=DHCP_MAX_VLAN) {
				if (diag)
					fprintf(diag,"Ignored too many vlans in packet: %d bytes\n",caplen);
				return 0;
			}
			f->vlan[f->nvlan].type=ntohs(*et)==ETH_P_8021Q?'C':'S';
			f->vlan[f->nvlan].id=ntohs(et[1])&0xfff;
			f->nvlan++;
			offset+=4;
			et+=2;
			goto nexthdr;
		default:
			if (diag)
				fprintf(diag,"Ignored non IPv4 packet: 0x%x\n",ntohs(eh->ether_type));
			return 0;
	}

	// Check for length
	if (caplen<offset+sizeof(struct ip)) {
		if (diag)
			fprintf(diag,"Ignored too short IPv4 packet: %d bytes\n",caplen);
		return 0;
	}

	ip=(const struct ip *)(sp+offset);
	ihl=ip->ip_hl;
	if (ihl<5)
		ihl=5;
	offset+=ihl*4;

	if (caplen<offset+sizeof(struct udphdr)) {
		if (diag)
			fprintf(diag,"Ignored too short UDP packet: %d bytes\n",caplen);
		return 0;
	}

	udp=(const struct udphdr *)(sp+offset);
	offset+=sizeof(struct udphdr);

	// Length of the DHCP payload: trust neither the UDP length field nor the
	// capture length on its own, use whichever is smaller. The UDP length
	// counts its own 8 byte header, the captured payload starts after it.
	plen=ntohs(udp->UDP_LEN_F);
	if (plen<sizeof(struct udphdr))
		plen=0;
	else
		plen-=sizeof(struct udphdr);
	if (plen>caplen-offset)
		plen=caplen-offset;

	memcpy(f->smac,eh->ether_shost,6);
	memcpy(f->dmac,eh->ether_dhost,6);
	f->srcip=ip->ip_src.s_addr;
	f->dstip=ip->ip_dst.s_addr;
	f->payload=sp+offset;
	f->plen=plen;

	return 1;
} // }}}

void dhcp_print(const struct dhcp_frame *f,const char *ts) { // {{{ classic verbose dump of a decapsulated frame
	char sip[40],dip[40],smac[40],dmac[40];
	int i;

	if (f->nvlan)
		printf("  VLAN:");
	for (i=0;i<f->nvlan;i++)
		printf(" %c:%04u",f->vlan[i].type,f->vlan[i].id);
	if (f->nvlan)
		printf("\n");

	inet_ntop(AF_INET,&f->srcip,sip,sizeof sip);
	inet_ntop(AF_INET,&f->dstip,dip,sizeof dip);
	snprintf(smac,sizeof smac,"%02x:%02x:%02x:%02x:%02x:%02x",
		f->smac[0],f->smac[1],f->smac[2],f->smac[3],f->smac[4],f->smac[5]);
	snprintf(dmac,sizeof dmac,"%02x:%02x:%02x:%02x:%02x:%02x",
		f->dmac[0],f->dmac[1],f->dmac[2],f->dmac[3],f->dmac[4],f->dmac[5]);

	print_payload(f->payload,f->plen,ts,sip,smac,dip,dmac);
} // }}}
