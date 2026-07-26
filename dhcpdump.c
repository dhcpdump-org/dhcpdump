// {{{ includes

#include <err.h>
#include <pcap.h>
#include <time.h>
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include "version.h"
#include "dhcp_options.h"

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

// {{{ globals

char timestamp[40]; // timestamp on header
char mac_orig[40]; // mac address of origin
char mac_dest[40]; // mac address of destination
char ip_orig[40]; // ip address of origin
char ip_dest[40]; // ip address of destination
int max_data_len; // maximum size of a packet
int dohexdump=0; // dump whole packet contents for debug

int tcpdump_style=-1;
char errbuf[PCAP_ERRBUF_SIZE];
char *hmask=NULL;
regex_t preg;

// }}}

static inline int usage(const char *me) { // {{{
	printf("dhcpdump "VERSION"\n");
	printf("  Usage:\n");
	printf("    %s -i <interface> [-h <macaddress>] [-H]\n",me);
	printf("    %s -r <pcapfile>  [-h <macaddress>] [-H]\n",me);
	printf("  Options:\n");
	printf("    -h regexp filter by <macaddress>\n");
	printf("    -H prints whole packet hex dump\n");
	return 0;
} // }}}

static inline int check_ch(uint8_t *data,int data_len) { // {{{ check for matching CHADDR (Peter Apian-Bennewitz <apian@ise.fhg.de>)
	char ch_ip[50];

	if (data_len<44) // CHADDR spans data[28..43], so 44 bytes must be present
		return 0;

	sprintf(ch_ip,
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		data[28],data[29],data[30],data[31],
		data[32],data[33],data[34],data[35],
		data[36],data[37],data[38],data[39],
		data[40],data[41],data[42],data[43]);

	return regexec(&preg,ch_ip,0,NULL,0);
} // }}}

static inline void printIPaddress(uint8_t *data) { // {{{ print the data as an IP address
	printf("%u.%u.%u.%u",data[0],data[1],data[2],data[3]);
} // }}}

static inline void printIPaddressAddress(uint8_t *data) { // {{{ print the data as an IP address and an IP address
	printf("%u.%u.%u.%u %u.%u.%u.%u",
		data[0],data[1],data[2],data[3],
		data[4],data[5],data[6],data[7]);
} // }}}

static inline void printIPaddressMask(uint8_t *data) { // {{{ print the data as an IP address and mask
	printf("%u.%u.%u.%u/%u.%u.%u.%u",
		data[0],data[1],data[2],data[3],
		data[4],data[5],data[6],data[7]);
} // }}}

static inline void print8bits(uint8_t *data) { // {{{ prints a value of 8 bits (1 byte)
	printf("%u",data[0]);
} // }}}

static inline void print16bits(uint8_t *data) { // {{{ prints a value of 16 bits (2 bytes)
	printf("%u",(data[0]<<8)|data[1]);
} // }}}

static inline void printTime8(uint8_t *data) { // {{{ print the data as a 8bits time-value
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

static inline void printTime32(uint8_t *data) { // {{{ print the data as a 32bits time-value
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

static inline void printHexString(uint8_t *data,int len,int clen) { // {{{ print the data as a hex-list, with the translation into ascii behind it
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

static inline void printHex(uint8_t *data,int len) { // {{{ print the data as a hex-list, without the translation into ascii behind it
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

static inline void printHexColon(uint8_t *data,int len) { // {{{ print the data as a hex-list separated by colons
	int i;

	for (i=0;i<len;i++) {
		if (i!=0)
			printf(":");
		printf("%02x",data[i]);
	}
} // }}}

static inline void printReqParmList(uint8_t *data,int len) { // {{{ print the list of requested parameters
	int i;

	for (i=0;i<len;i++)
		printf("%-3d (%s)%s%*s",data[i],dhcp_options[data[i]],(i+1<len)?"\n":"",(i+1<len)?44:0,"");
} // }}}

static inline void printIPaddressCompactMaskAddress(uint8_t *data,int len) { // {{{ print the data as series of IP address and masks
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

static inline int printdata(uint8_t *data,int data_len) { // {{{ print the header and the options.
	char buf[LARGESTRING];
	int i,j;

	if (data_len==0)
		return 0;

	if (data_len<236) { // the fixed BOOTP header (op..file) is 236 bytes
		fprintf(stderr,"Ignored too short DHCP packet: %d bytes\n",data_len);
		return 0;
	}

	printf("  TIME: %s\n",timestamp);
	printf("    IP: %s (%s) > %s (%s)\n",ip_orig,mac_orig,ip_dest,mac_dest);
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

	return 0;
} // }}}

static inline void hexdump(const uint8_t *buf,int len) { // {{{
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

static void pcap_callback(uint8_t *user __attribute__((unused)),const struct pcap_pkthdr *h,const uint8_t *sp) { // {{{
	struct ether_header *eh;
	struct udphdr *udp;
	struct timeval tp;
	unsigned offset=0;
	uint8_t vlans[20];
	unsigned vlanc=0;
	char vlant[20];
	struct ip *ip;
	uint16_t *et;
	unsigned ihl;
	unsigned plen;
	unsigned i;

	if (dohexdump) {
		hexdump(sp,h->caplen);
		printf("\n");
	}

	if (h->caplen<ETHER_HDR_LEN) {
		fprintf(stderr,"Ignored too short ethernet packet: %d bytes\n",h->caplen);
		return;
	}

	eh=(struct ether_header *)(sp+offset);
	et=(uint16_t *)(sp+offset+sizeof *eh);
	et--;

	// Check for IPv4 packets
nexthdr:
	switch (ntohs(*et)) {
		case ETH_P_IP:
			offset+=ETHER_HDR_LEN;
			break;
		case ETH_P_8021Q:
		case ETH_P_8021AD:
			if (h->caplen<ETHER_HDR_LEN+offset+4) {
				fprintf(stderr,"Ignored too short ethernet+vlan packet: %d bytes\n",h->caplen);
				return;
			}
			if (vlanc>=sizeof vlant/sizeof *vlant) {
				fprintf(stderr,"Ignored too many vlans in packet: %d bytes\n",h->caplen);
				return;
			}
			vlant[vlanc]=ntohs(*et)==ETH_P_8021Q?'C':'S';
			vlans[vlanc]=ntohs(et[1])&0xfff;
			vlanc++;
			offset+=4;
			et+=2;
			goto nexthdr;
		default:
			fprintf(stderr,"Ignored non IPv4 packet: 0x%x\n",ntohs(eh->ether_type));
			return;
	}

	// Check for length
	if (h->caplen<offset+sizeof(struct ip)) {
		fprintf(stderr,"Ignored too short IPv4 packet: %d bytes\n",h->caplen);
		return;
	}

	ip=(struct ip *)(sp+offset);
	ihl=ip->ip_hl;
	if (ihl<5)
		ihl=5;
	offset+=ihl*4;

	if (h->caplen<offset+sizeof(struct udphdr)) {
		fprintf(stderr,"Ignored too short UDP packet: %d bytes\n",h->caplen);
		return;
	}

	udp=(struct udphdr *)(sp+offset);
	offset+=sizeof(struct udphdr);

	// Length of the DHCP payload: trust neither the UDP length field nor the
	// capture length on its own, use whichever is smaller. The UDP length
	// counts its own 8 byte header, the captured payload starts after it.
	plen=ntohs(udp->UDP_LEN_F);
	if (plen<sizeof(struct udphdr))
		plen=0;
	else
		plen-=sizeof(struct udphdr);
	if (plen>h->caplen-offset)
		plen=h->caplen-offset;

	gettimeofday(&tp,NULL);
	strftime(timestamp,sizeof timestamp,"%Y-%m-%d %H:%M:%S.",localtime(&(tp.tv_sec)));
	sprintf(timestamp+strlen(timestamp),"%03ld",tp.tv_usec/1000);

	sprintf(mac_orig,"%02x:%02x:%02x:%02x:%02x:%02x",
		eh->ether_shost[0],eh->ether_shost[1],eh->ether_shost[2],
		eh->ether_shost[3],eh->ether_shost[4],eh->ether_shost[5]);
	sprintf(mac_dest,"%02x:%02x:%02x:%02x:%02x:%02x",
		eh->ether_dhost[0],eh->ether_dhost[1],eh->ether_dhost[2],
		eh->ether_dhost[3],eh->ether_dhost[4],eh->ether_dhost[5]);

	ip_orig[0]=0;
	ip_dest[0]=0;
	inet_ntop(AF_INET,&ip->ip_src,ip_orig,sizeof ip_orig);
	inet_ntop(AF_INET,&ip->ip_dst,ip_dest,sizeof ip_dest);

	if (hmask&&check_ch((uint8_t *)(sp+offset),plen))
		return;

	if (vlanc)
		printf("  VLAN:");
	for (i=0;i<vlanc;i++)
		printf(" %c:%04u",vlant[i],vlans[i]);
	if (vlanc)
		printf("\n");
	printdata((uint8_t *)(sp+offset),plen);
} // }}}

int main(int argc,char **argv) { // {{{
	struct bpf_program fp;
	char *interface=NULL;
	char *pcapfile=NULL;
	pcap_t *cap;
	int i;

	for (i=1;i<argc;i++) {
		if (argv[i]==NULL||argv[i][0]!='-')
			break;
		switch (argv[i][1]) {
			case 'H':
				dohexdump=1;
				break;
			case 'h':
				hmask=argv[++i];
				break;
			case 'i':
				interface=argv[++i];
				break;
			case 'r':
				pcapfile=argv[++i];
				break;
			default:
				fprintf(stderr,"%s: %c: unknown option\n",argv[0],argv[i][1]);
				return usage(argv[0]);
		}
	}

	if (interface==NULL&&pcapfile==NULL)
		return usage(argv[0]);
	if (interface!=NULL&&pcapfile!=NULL)
		errx(1,"Can not capture from interface \"%s\" and read from file \"%s\" at the same time",interface,pcapfile);

	if (hmask) {
		int rc=regcomp(&preg,hmask,REG_EXTENDED|REG_ICASE|REG_NOSUB);

		if (rc) {
			char rerr[LARGESTRING];

			regerror(rc,&preg,rerr,sizeof rerr);
			errx(1,"Invalid -h regexp \"%s\": %s",hmask,rerr);
		}
	}

	if (interface!=NULL) {
		if ((cap=pcap_open_live(interface,1500,1,100,errbuf))==NULL)
			errx(1,"pcap_open_live(): %s",errbuf);
	} else {
		if ((cap=pcap_open_offline(pcapfile,errbuf))==NULL)
			errx(1,"pcap_open_offline(): %s",errbuf);
	}
	if (pcap_compile(cap,&fp,"ip and udp and (src port bootpc or bootps) and (dst port bootpc or bootps)",0,0)<0)
		errx(1,"pcap_compile: %s",pcap_geterr(cap));
	if (pcap_setfilter(cap,&fp)<0)
		errx(1,"pcap_setfilter: %s",pcap_geterr(cap));
	if (pcap_loop(cap,0,pcap_callback,NULL)<0)
		errx(1,"pcap_loop(%s): %s",interface,pcap_geterr(cap));

	return 0;
} // }}}
