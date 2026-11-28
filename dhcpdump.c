// {{{ includes

#include <time.h>
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
#include "json.h"

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
#define OPTLISTCOL 18 // indent for multi line lists, one item per line under the option header; right of the option names so the items read as nested
#define OPTHEXCOL 9 // indent for hex+ascii block values: the width of the hex dump's address column, so an option block renders like the trailing hex dump with the address blanked and aligns with it

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
// Bar glyph around the ascii columns of hex dumps and hex+ascii blocks; set
// together with g_out (the TUI passes a box drawing glyph in UTF-8 mode).
static const char *g_bar="|";
// Whether to tag the generated <overloaded> sname/file marker with a leading
// \1 byte. Packet data can never render a control byte (is_printable diverts
// it to a hex block), so the tag lets the TUI colour only the genuine marker
// and leave a crafted literal "<overloaded>" field value alone. Off for the
// line dump, whose output must stay free of control bytes.
static int g_ovmark=0;

static const uint8_t dhcp_cookie[4]={99,130,83,99}; // RFC 2131 magic cookie, marks the start of the option list

static inline void printIPaddress(const uint8_t *data) { // {{{ print the data as an IP address
	fprintf(g_out,"%u.%u.%u.%u",data[0],data[1],data[2],data[3]);
} // }}}

static inline void print8bits(const uint8_t *data) { // {{{ prints a value of 8 bits (1 byte)
	fprintf(g_out,"%u",data[0]);
} // }}}

static inline void print16bits(const uint8_t *data) { // {{{ prints a value of 16 bits (2 bytes)
	fprintf(g_out,"%u",(unsigned)((data[0]<<8)|data[1]));
} // }}}

static inline void printTimeVal(long long t) { // {{{ print a seconds count raw, followed by its w/d/h/m/s breakdown; a negative count gets a minus in front of both
	unsigned rest=t<0?0u-(unsigned)t:(unsigned)t; // the magnitude; callers pass 32 bit values
	int any=0;

	fprintf(g_out,"%lld (%s",t,t<0?"-":"");
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

static inline unsigned be16(const uint8_t *p) { // {{{ read 2 network order bytes into a host order value, with no alignment requirement
	return ((unsigned)p[0]<<8)|p[1];
} // }}}

static inline uint32_t be32(const uint8_t *p) { // {{{ read 4 network order bytes into a host order value
	// cast before shifting; p[0]<<24 on its own promotes to int and overflows
	return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
} // }}}

static inline long be32s(const uint8_t *p) { // {{{ read 4 network order bytes as a signed two's complement value
	uint32_t t=be32(p);

	return t&0x80000000u?-(long)(~t)-1:(long)t; // by hand; a cast to int32_t is implementation defined before C23
} // }}}

static inline void printTime32(const uint8_t *data) { // {{{ print the data as a 32bits time-value
	printTimeVal(be32(data));
} // }}}

static inline void printTimeOffset32(const uint8_t *data) { // {{{ print the data as a signed 32bits time-value (RFC 2132 3.4: seconds east of UTC, negative west of it)
	printTimeVal(be32s(data));
} // }}}

static inline void printEpoch32(const uint8_t *data) { // {{{ print the data as a 32bits absolute time (seconds since the epoch), followed by it as local time
	time_t t=be32(data);
	struct tm tm;
	char b[32];

	fprintf(g_out,"%lu",(unsigned long)be32(data));
	if (localtime_r(&t,&tm)&&strftime(b,sizeof b,"%Y-%m-%d %H:%M:%S",&tm))
		fprintf(g_out," (%s)",b);
} // }}}

static void print_hex_row(const uint8_t *data,int n) { // {{{ one hexdump line without its address column: 16 byte positions as spaced hex in two groups, then the ascii in bars, both space padded so the bars always line up
	int j;

	for (j=0;j<16;j++) {
		if (j%8==0)
			fprintf(g_out," ");
		if (j<n)
			fprintf(g_out,"%02x ",data[j]);
		else
			fprintf(g_out,"   ");
	}
	fprintf(g_out," %s",g_bar);
	for (j=0;j<16;j++) {
		if (j<n) {
			unsigned char c=data[j]; // isprint() is undefined for a negative char

			fprintf(g_out,"%c",isprint(c)?c:'.');
		} else
			fprintf(g_out," ");
	}
	fprintf(g_out,"%s",g_bar);
} // }}}

static inline void printHexBlock(const uint8_t *data,int len) { // {{{ print the data below the option header, formatted like the trailing packet hex dump with the address column blanked, so bytes, bars and ascii line up with it
	int i;

	for (i=0;i<len;i+=16) {
		fprintf(g_out,"\n%*s",OPTHEXCOL,"");
		print_hex_row(data+i,len-i>16?16:len-i);
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

static inline void printList(const uint8_t *data,int len,int itemsz,char pairsep) { // {{{ print a multi value list: the first item on the header line, every next one on its own line at the value column; an 8 byte item is two addresses joined by pairsep, a 2 byte item is a 16 bit value, else one address per item
	int i;

	for (i=0;i+itemsz<=len;i+=itemsz) {
		if (i)
			fprintf(g_out,"\n%*s",OPTVALCOL,"");
		if (itemsz==2)
			print16bits(data+i);
		else if (itemsz==8)
			fprintf(g_out,"%u.%u.%u.%u%c%u.%u.%u.%u",
				data[i],data[i+1],data[i+2],data[i+3],pairsep,
				data[i+4],data[i+5],data[i+6],data[i+7]);
		else
			printIPaddress(data+i);
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

static int croutes_ok(const uint8_t *data,int len) { // {{{ a well formed series of RFC 3442 compact routes: prefix length, its significant octets, router
	int i,j;

	if (len<5)
		return 0;
	for (i=0;i<len;i++) {
		j=4+(data[i]+7)/8;
		if (data[i]>32||len<i+j+1)
			return 0;
		i+=j;
	}
	return 1;
} // }}}

static inline void printIPaddressCompactMaskAddress(const uint8_t *data,int len) { // {{{ print the data as series of IP address and masks (croutes_ok must hold)
	int i,j;

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

static int adn_ok(const uint8_t *p,int n) { // {{{ exactly n bytes of one uncompressed DNS wire format name (RFC 8415 section 10): labels of 1 to 63 bytes, the last byte the root label
	int i=0;

	if (n<1)
		return 0;
	while (p[i]) {
		if (p[i]>63||i+1+p[i]>=n) // >=, so a root label still fits behind this one; over 63 also catches a compression pointer
			return 0;
		i+=1+p[i];
	}
	return i==n-1;
} // }}}

static int adn_text(const uint8_t *p,int n,char *b) { // {{{ the dotted form of an adn_ok name into b (n+1 bytes at least), without the trailing dot and "." for the root alone; 0 when a label byte is not printable or is a dot, which the dotted form cannot show
	int i,j,k=0;

	for (i=0;i<n&&p[i];i+=1+p[i]) { // i<n only for safety, adn_ok has ended the name with its root label
		for (j=1;j<=p[i];j++) {
			if (!isprint(p[i+j])||p[i+j]=='.')
				return 0;
			b[k++]=(char)p[i+j];
		}
		b[k++]='.';
	}
	if (k)
		k--;
	else
		b[k++]='.';
	b[k]=0;
	return 1;
} // }}}

static const char *svc_keyname(unsigned key,char *b,size_t bl) { // {{{ the name of a SvcParamKey, keyNNNNN (the RFC 9460 presentation form) for an unknown one
	if (key<strcountof(svc_keys))
		return svc_keys[key];
	snprintf(b,bl,"key%u",key);
	return b;
} // }}}

static int alpn_ok(const uint8_t *p,int n,int needprint) { // {{{ a non empty series of non empty length prefixed alpn ids filling exactly n bytes, with needprint also all printable
	int i;

	if (n<1)
		return 0;
	for (i=0;i<n;i+=1+p[i])
		if (!p[i]||i+1+p[i]>n||(needprint&&!is_printable(p+i+1,p[i])))
			return 0;
	return 1;
} // }}}

static int svc_value_ok(unsigned key,const uint8_t *p,int n) { // {{{ the value of a known SvcParamKey has its RFC 9460 wire format; the others are opaque
	switch (key) {
		case SVC_MANDATORY:
			return n>0&&n%2==0;
		case SVC_ALPN:
			return alpn_ok(p,n,0);
		case SVC_NODEFALPN:
		case SVC_OHTTP:
			return n==0;
		case SVC_PORT:
			return n==2;
		case SVC_IPV4HINT:
			return n>0&&n%4==0;
		case SVC_IPV6HINT:
			return n>0&&n%16==0;
	}
	return 1;
} // }}}

static const char *svcparams_malformed(const uint8_t *p,int n) { // {{{ why n bytes are not RFC 9460 section 2.2 SvcParams (key, length, value; keys strictly increasing), NULL if they are
	int i,key,vl,prev=-1;

	for (i=0;i<n;i+=4+vl) {
		if (i+4>n)
			return "truncated service parameter";
		key=(int)be16(p+i);
		vl=(int)be16(p+i+2);
		if (i+4+vl>n)
			return "service parameter too large";
		if (key<=prev)
			return "service parameters out of order";
		if (key==SVC_INVALID)
			return "invalid service parameter key";
		if (!svc_value_ok((unsigned)key,p+i+4,vl))
			return "bad service parameter value";
		prev=key;
	}
	return NULL;
} // }}}

static const char *dnr_malformed(const uint8_t *v,int len) { // {{{ why a value is not a series of RFC 9463 section 5.1 DNR instances, NULL if it is; when NULL, every length in it is known to be in bounds
	const char *why;
	int i,n,al,xl;

	if (len<1)
		return "too short";
	for (i=0;i<len;i+=2+n) {
		if (i+2>len)
			return "truncated instance";
		n=(int)be16(v+i); // instance data length, of what follows it
		if (i+2+n>len)
			return "instance too large";
		if (n<3) // service priority and ADN length are mandatory
			return "instance too short";
		al=v[i+4];
		if (3+al>n)
			return "ADN too large";
		if (!adn_ok(v+i+5,al))
			return "bad ADN";
		if (n==3+al) // ADN-only mode, no addresses and no service parameters
			continue;
		xl=v[i+5+al];
		if (4+al+xl>n)
			return "addresses too large";
		if (!xl) // when present, one address at least (RFC 9463 section 3.1.8)
			return "no addresses";
		if (xl%4)
			return "addresses not a multiple of 4";
		why=svcparams_malformed(v+i+6+al+xl,n-4-al-xl);
		if (why)
			return why;
	}
	return NULL;
} // }}}

static const char *opt_malformed(int type,const uint8_t *v,int len) { // {{{ why a value does not fit its option type, NULL if it does; every renderer decides by this, so they agree on what is malformed
	switch (type) {
		case OT_ADDR:
		case OT_SECS:
		case OT_EPOCH:
		case OT_TIMEOFFSET:
			return len<4?"too short":NULL;
		case OT_U16:
			return len<2?"too short":NULL;
		case OT_U8:
		case OT_ENUM:
		case OT_HEX:
			return len<1?"too short":NULL;
		case OT_FQDN: // flags and both rcodes are mandatory
		case OT_NDI:
			return len<3?"too short":NULL;
		case OT_ADDRS:
			return len<4?"too short":len%4?"length not a multiple of 4":NULL;
		case OT_SLPDA:
			return len<1?"too short":(len-1)%4?"addresses not a multiple of 4":NULL;
		case OT_ADDRMASKS:
		case OT_ROUTES:
			return len<8?"too short":len%8?"length not a multiple of 8":NULL;
		case OT_U16S:
		case OT_ARCH:
			return len<2?"too short":len%2?"length not a multiple of 2":NULL;
		case OT_CROUTES:
			return croutes_ok(v,len)?NULL:"bad route encoding";
		case OT_DNR:
			return dnr_malformed(v,len);
	}
	return NULL; // text, the parameter request list and relay sub-options take any length
} // }}}

static inline int opt_is_inline(int o) { // {{{ options whose value always starts on the header line, so the name is padded out to OPTVALCOL: every structured type except the two that list their items below the header
	switch (opt_info[o].type) {
		case OT_TEXT:
		case OT_PRL:
		case OT_RELAY:
		case OT_DNR:
			return 0;
	}
	return 1;
} // }}}

static inline int opt_is_str(int o) { // {{{ options rendered as text when the value is fully printable and as a hex+ascii block below the header otherwise: everything without a structured type
	return opt_info[o].type==OT_TEXT;
} // }}}

static void printSubItem(const char *name,int inl) { // {{{ start a sub-item line under the option header, its name at OPTLISTCOL like a relay agent sub-option; padded out to OPTVALCOL only when inl, i.e. when its value follows on this line
	if (inl)
		fprintf(g_out,"\n%*s%-*s",OPTLISTCOL,"",OPTVALCOL-OPTLISTCOL,name);
	else
		fprintf(g_out,"\n%*s%s",OPTLISTCOL,"",name);
} // }}}

static void printSvcParam(unsigned key,const uint8_t *p,int n) { // {{{ one service parameter of a DNR instance (svcparams_malformed must hold NULL): known keys decoded, one list item per line, the rest as hex+ascii
	char b[INET6_ADDRSTRLEN],kb[16];
	const char *name=svc_keyname(key,kb,sizeof kb);
	int i;

	switch (key) {
		default: // ech and unknown keys are opaque
			printSubItem(name,0);
			printHexBlock(p,n);
			break;
		case SVC_NODEFALPN:
		case SVC_OHTTP: // no value
			printSubItem(name,0);
			break;
		case SVC_MANDATORY:
			printSubItem(name,1);
			for (i=0;i+2<=n;i+=2) {
				if (i)
					fprintf(g_out,"\n%*s",OPTVALCOL,"");
				fprintf(g_out,"%s",svc_keyname(be16(p+i),kb,sizeof kb));
			}
			break;
		case SVC_ALPN:
			if (!alpn_ok(p,n,1)) {
				printSubItem(name,0);
				printHexBlock(p,n);
				break;
			}
			printSubItem(name,1);
			for (i=0;i<n;i+=1+p[i]) {
				if (i)
					fprintf(g_out,"\n%*s",OPTVALCOL,"");
				printWrapped(p+i+1,p[i],OPTVALCOL,OPTVALCOL,OPTWRAPCOL);
			}
			break;
		case SVC_PORT:
			printSubItem(name,1);
			fprintf(g_out,"%u",be16(p));
			break;
		case SVC_IPV4HINT:
			printSubItem(name,1);
			printList(p,n,4,' ');
			break;
		case SVC_IPV6HINT:
			printSubItem(name,1);
			for (i=0;i+16<=n;i+=16) {
				if (i)
					fprintf(g_out,"\n%*s",OPTVALCOL,"");
				fprintf(g_out,"%s",inet_ntop(AF_INET6,p+i,b,sizeof b)?b:"?");
			}
			break;
		case SVC_DOHPATH:
			if (n>0&&is_printable(p,n)) {
				printSubItem(name,1);
				printWrapped(p,n,OPTVALCOL,OPTVALCOL,OPTWRAPCOL);
			} else {
				printSubItem(name,0);
				printHexBlock(p,n);
			}
			break;
	}
} // }}}

static void printDNR(const uint8_t *v,int len) { // {{{ the DNR instances of option 162 (dnr_malformed must hold NULL), each as its priority, ADN, addresses and service parameters on lines of their own
	char adn[256];
	const uint8_t *p;
	int i,j,n,al,xl,vl;

	for (i=0;i<len;i+=2+n) {
		n=(int)be16(v+i);
		al=v[i+4];
		printSubItem("priority",1);
		fprintf(g_out,"%u",be16(v+i+2));
		if (adn_text(v+i+5,al,adn)) {
			printSubItem("adn",1);
			printWrapped((const uint8_t *)adn,(int)strlen(adn),OPTVALCOL,OPTVALCOL,OPTWRAPCOL);
		} else {
			printSubItem("adn",0);
			printHexBlock(v+i+5,al);
		}
		if (n==3+al) // ADN-only mode
			continue;
		xl=v[i+5+al];
		printSubItem("addrs",1);
		printList(v+i+6+al,xl,4,' ');
		p=v+i+6+al+xl;
		for (j=0;j<n-4-al-xl;j+=4+vl) {
			vl=(int)be16(p+j+2);
			printSvcParam(be16(p+j),p+j+4,vl);
		}
	}
} // }}}

static void print_option_area(const uint8_t *data,int data_len) { // {{{ decode one TLV option area: the options field past the cookie, or an overloaded sname/file field (RFC 2131 option overload)
	char buf[LARGESTRING];
	int i,j=0,valcol,nl;

	while (j<data_len&&data[j]!=255) {
		const struct opt_info *oi;
		const uint8_t *v;
		const char *why;
		int len;

		if (data[j]==0) { // pad option, carries neither a length nor a value byte
			fprintf(g_out,"OPTION: %3d (  0) %s\n",data[j],dhcp_options[data[j]]);
			j++;
			continue;
		}
		if (j+2>data_len||j+2+data[j+1]>data_len) { // length byte and value bytes must be captured
			fprintf(g_out,"OPTION: %3d       *malformed - truncated option*\n",data[j]);
			break;
		}
		oi=&opt_info[data[j]];
		v=data+j+2;
		len=data[j+1];
		why=opt_malformed(oi->type,v,len);
		nl=(int)strlen(dhcp_options[data[j]]);
		valcol=18+(nl>26?nl+1:26); // where the value starts (a name too long for the pad pushes it right, keeping one separating space)
		// pad the name out to the value column only when a value actually
		// follows on this line, otherwise the padding is trailing whitespace
		if (opt_is_inline(data[j])||(opt_is_str(data[j])&&len>0&&is_printable(v,len)))
			fprintf(g_out,"OPTION: %3d (%3d) %-*s",data[j],len,nl>26?nl+1:26,dhcp_options[data[j]]);
		else // value rendered on its own lines below: header carries only the name
			fprintf(g_out,"OPTION: %3d (%3d) %s",data[j],len,dhcp_options[data[j]]);

		switch (oi->type) { // renderers by value type (opt_info in dhcp_options.h); a malformed value says so instead
			default: // OT_TEXT: a wholly printable value prints as text on the header line; the typically binary ones (43 vendor specific, 61 client id, ...) fail that check and drop to a hex+ascii block
				if (len>0&&is_printable(v,len))
					printWrapped(v,len,valcol,OPTVALCOL,OPTWRAPCOL);
				else
					printHexBlock(v,len);
				break;

			case OT_ADDR:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					printIPaddress(v);
				break;

			case OT_ADDRS:
				if (why) { // not a whole number of addresses: dump instead of inventing one
					fprintf(g_out,"*malformed*");
					printHexBlock(v,len);
				} else
					printList(v,len,4,' ');
				break;

			case OT_SLPDA:
				if (why) {
					fprintf(g_out,"*malformed*");
					printHexBlock(v,len);
					break;
				}
				fprintf(g_out,"%u (%s)",v[0],v[0]?"mandatory":"optional");
				if (len>1) {
					fprintf(g_out,"\n%*s",OPTVALCOL,"");
					printList(v+1,len-1,4,' ');
				}
				break;

			case OT_ADDRMASKS:
			case OT_ROUTES:
				if (why) {
					fprintf(g_out,"*malformed*");
					printHexBlock(v,len);
				} else
					printList(v,len,8,oi->type==OT_ADDRMASKS?'/':' ');
				break;

			case OT_U16S:
				if (why) {
					fprintf(g_out,"*malformed*");
					printHexBlock(v,len);
				} else
					printList(v,len,2,' ');
				break;

			case OT_U16:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					print16bits(v);
				break;

			case OT_U8:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					print8bits(v);
				break;

			case OT_TIMEOFFSET:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					printTimeOffset32(v);
				break;

			case OT_SECS:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					printTime32(v);
				break;

			case OT_EPOCH:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					printEpoch32(v);
				break;

			case OT_ENUM:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%d (%s)",v[0],v[0]>=oi->nnames?"*unknown*":oi->names[v[0]]);
				break;

			case OT_HEX:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					printHex(v,len);
				break;

			case OT_PRL:
				printReqParmList(v,len);
				break;

			case OT_FQDN:
				if (why) {
					fprintf(g_out,"*malformed - too short*");
					break;
				}
				print8bits(v);
				fprintf(g_out,"-");
				print8bits(v+1);
				fprintf(g_out,"-");
				print8bits(v+2);
				if (len==3) // flags and rcodes only, no name follows
					break;
				if (is_printable(v+3,len-3)) {
					fprintf(g_out," ");
					strncpy(buf,(const char *)v+3,len-3);
					buf[len-3]=0;
					fprintf(g_out,"%s",buf);
				} else // the E flag makes the name DNS wire format; escapes in a plain name are handled the same way
					printHexBlock(v+3,len-3);
				break;

			case OT_RELAY:
				for (i=j+2;i<j+data[j+1]+2;) {
					const char *sn;

					if (i+2>j+data[j+1]+2) { // suboption code and length bytes must be present
						fprintf(g_out,"\n%-17s *malformed - truncated*"," ");
						break;
					}
					sn=data[i]>=strcountof(relayagent_suboptions)?"*unknown*":relayagent_suboptions[data[i]];
					if (i+data[i+1]+2>j+data[j+1]+2) {
						fprintf(g_out,"\n%-17s %s *malformed - too large*\n"," ",sn);
						break;
					}
					// a wholly printable value sits on the suboption's line like
					// an inline option value, anything else in a hex+ascii block
					if (data[i+1]>0&&is_printable(data+i+2,data[i+1])) {
						fprintf(g_out,"\n%-17s %-26s"," ",sn);
						printWrapped(data+i+2,data[i+1],OPTVALCOL,OPTVALCOL,OPTWRAPCOL);
					} else {
						fprintf(g_out,"\n%-17s %s"," ",sn);
						printHexBlock(data+i+2,data[i+1]);
					}
					i+=data[i+1]+2;
				}
				break;

			case OT_ARCH: // a list of 16 bit type values
				if (why) {
					fprintf(g_out,"*malformed*");
					printHexBlock(v,len);
				} else
					for (i=0;i<len;i+=2) {
						unsigned a=((unsigned)v[i]<<8)|v[i+1];

						if (i)
							fprintf(g_out,"\n%*s",OPTVALCOL,"");
						fprintf(g_out,"%u (%s)",a,a>=strcountof(client_architecture_names)?"*unknown*":client_architecture_names[a]);
					}
				break;

			case OT_NDI:
				if (why)
					fprintf(g_out,"*malformed - too short*");
				else
					fprintf(g_out,"%u (Rev %d.%d)",(unsigned)(v[1]<<8|v[2]),v[1],v[2]);
				break;

			case OT_CROUTES:
				if (why) {
					fprintf(g_out,"Malformed\n%44s","");
					printHex(v,len);
				} else
					printIPaddressCompactMaskAddress(v,len);
				break;

			case OT_DNR:
				if (why) {
					fprintf(g_out,"\n%*s*malformed - %s*",OPTLISTCOL,"",why);
					printHexBlock(v,len);
				} else
					printDNR(v,len);
				break;
		}
		fprintf(g_out,"\n");

		j+=len+2;
	}
} // }}}

static int find_overload(const uint8_t *data,int data_len) { // {{{ option 52 value (bit 0: file, bit 1: sname hold options), 0 if absent (caller ensures data_len>=DHCP_FIXED)
	int j,overload=0;

	if (data_len>=DHCP_FIXED+4&&!memcmp(data+DHCP_FIXED,dhcp_cookie,4)) {
		j=DHCP_FIXED+4;
		while (j<data_len&&data[j]!=255) {
			if (data[j]==0) {
				j++;
				continue;
			}
			if (j+2>data_len||j+2+data[j+1]>data_len)
				break;
			if (data[j]==52&&data[j+1]>=1)
				overload=data[j+2]&3;
			j+=data[j+1]+2;
		}
	}
	return overload;
} // }}}

static void print_bootp(const uint8_t *data,int data_len) { // {{{ print the BOOTP header and the options (caller ensures data_len>=DHCP_FIXED)
	// Option 52 relocates options into the sname/file header fields; find it
	// first, it decides below whether those fields hold names or options.
	int i,overload=find_overload(data,data_len);

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
	if (overload&2) // the field carries options instead, printed below with the rest
		fprintf(g_out," SNAME: %s<overloaded>\n",g_ovmark?"\1":"");
	else if (i==0) // empty prints as empty, not as a legacy lone dot
		fprintf(g_out," SNAME:\n");
	else if (is_printable(data+44,i))
		fprintf(g_out," SNAME: %.64s\n",data+44);
	else {
		fprintf(g_out," SNAME:");
		printHexBlock(data+44,i);
		fprintf(g_out,"\n");
	}
	i=(int)strnlen((const char *)(data+108),128); // file is a fixed 128 byte field, may lack a NUL
	if (overload&1)
		fprintf(g_out," FNAME: %s<overloaded>\n",g_ovmark?"\1":"");
	else if (i==0)
		fprintf(g_out," FNAME:\n");
	else if (is_printable(data+108,i))
		fprintf(g_out," FNAME: %.128s\n",data+108);
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
	print_option_area(data+DHCP_FIXED+4,data_len-DHCP_FIXED-4);
	if (overload&1) // the file field's options, then sname's, in RFC 3396 order
		print_option_area(data+108,128);
	if (overload&2)
		print_option_area(data+44,64);
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
	g_bar="|";
	g_ovmark=0;

	if (f->plen==0) // UDP with no payload at all: nothing to show
		return;

	if (f->nvlan)
		fprintf(g_out,"  VLAN:");
	for (i=0;i<f->nvlan;i++)
		fprintf(g_out," %c:%04u",f->vlan[i].type,f->vlan[i].id);
	if (f->nvlan)
		fprintf(g_out,"\n");

	inet_ntop(AF_INET,&f->srcip,sip,sizeof sip);
	inet_ntop(AF_INET,&f->dstip,dip,sizeof dip);
	snprintf(smac,sizeof smac,"%02x:%02x:%02x:%02x:%02x:%02x",
		f->smac[0],f->smac[1],f->smac[2],f->smac[3],f->smac[4],f->smac[5]);
	snprintf(dmac,sizeof dmac,"%02x:%02x:%02x:%02x:%02x:%02x",
		f->dmac[0],f->dmac[1],f->dmac[2],f->dmac[3],f->dmac[4],f->dmac[5]);

	fprintf(g_out,"  TIME: %s\n",ts);
	fprintf(g_out,"    IP: %s (%s) > %s (%s)\n",sip,smac,dip,dmac);
	if (f->plen<DHCP_FIXED) // too short for the fixed BOOTP header (op..file): say so in the output itself, this renders to whatever stream the caller chose and stderr is not its business
		fprintf(g_out,"*truncated - %d bytes*\n",f->plen);
	else
		print_bootp(f->payload,f->plen);
	fprintf(g_out,"--------------------------------------------------------------------------------\n\n");
	fflush(g_out);
} // }}}

void dhcp_print(const struct dhcp_frame *f,const char *ts) { // {{{ classic verbose dump to stdout
	dhcp_fprint(stdout,f,ts);
} // }}}

static void hexdump_c(const uint8_t *data,int len) { // {{{ hexdump -C style dump to g_out, the ascii in g_bar separators
	int i;

	for (i=0;i<len;i+=16) {
		fprintf(g_out,"%08x ",(unsigned)i);
		print_hex_row(data+i,len-i>16?16:len-i);
		fprintf(g_out,"\n");
	}
} // }}}

void dhcp_fprint_payload(FILE *out,const uint8_t *data,int data_len,const char *bar) { // {{{ decode + hex dump of a DHCP payload (TUI packet detail)
	g_out=out;
	g_bar=bar?bar:"|";
	g_ovmark=1;
	if (data_len<DHCP_FIXED) {
		fprintf(g_out,"*truncated - %d bytes*\n",data_len);
		return;
	}
	print_bootp(data,data_len);
	fprintf(g_out,"\n");
	hexdump_c(data,data_len);
} // }}}

// {{{ JSON output (-j)

static int json_allhex; // -H: every option and relay sub-option also carries its raw bytes as hex

static void json_svcparam(struct jw *w,unsigned key,const uint8_t *p,int n) { // {{{ one service parameter of a DNR instance (svcparams_malformed must hold NULL), decoded like printSvcParam
	char b[INET6_ADDRSTRLEN];
	int i;

	jw_obj(w,NULL);
	jw_uint(w,"key",key);
	if (key<strcountof(svc_keys))
		jw_str(w,"name",svc_keys[key]);
	switch (key) {
		default: // ech and unknown keys are opaque
			if (n>0)
				jw_hex(w,"hex",p,n);
			break;
		case SVC_NODEFALPN:
		case SVC_OHTTP: // no value
			break;
		case SVC_MANDATORY:
			jw_arr(w,"value");
			for (i=0;i+2<=n;i+=2)
				jw_uint(w,NULL,be16(p+i));
			jw_end(w);
			break;
		case SVC_ALPN:
			if (!alpn_ok(p,n,1)) {
				jw_hex(w,"hex",p,n);
				break;
			}
			jw_arr(w,"value");
			for (i=0;i<n;i+=1+p[i])
				jw_strn(w,NULL,p+i+1,p[i]);
			jw_end(w);
			break;
		case SVC_PORT:
			jw_uint(w,"value",be16(p));
			break;
		case SVC_IPV4HINT:
			jw_arr(w,"value");
			for (i=0;i+4<=n;i+=4)
				jw_ip(w,NULL,p+i);
			jw_end(w);
			break;
		case SVC_IPV6HINT:
			jw_arr(w,"value");
			for (i=0;i+16<=n;i+=16)
				if (inet_ntop(AF_INET6,p+i,b,sizeof b))
					jw_str(w,NULL,b);
			jw_end(w);
			break;
		case SVC_DOHPATH:
			if (n>0&&is_printable(p,n))
				jw_strn(w,"value",p,n);
			else if (n>0)
				jw_hex(w,"hex",p,n);
			break;
	}
	jw_end(w);
} // }}}

static void json_dnr(struct jw *w,const uint8_t *v,int len) { // {{{ the DNR instances of option 162 (dnr_malformed must hold NULL) as a list of objects, decoded like printDNR
	char adn[256];
	const uint8_t *p;
	int i,j,n,al,xl,vl;

	jw_arr(w,"value");
	for (i=0;i<len;i+=2+n) {
		n=(int)be16(v+i);
		al=v[i+4];
		jw_obj(w,NULL);
		jw_uint(w,"priority",be16(v+i+2));
		if (adn_text(v+i+5,al,adn))
			jw_str(w,"adn",adn);
		else
			jw_hex(w,"adn_hex",v+i+5,al);
		if (n>3+al) { // not ADN-only mode
			xl=v[i+5+al];
			jw_arr(w,"addrs");
			for (j=0;j+4<=xl;j+=4)
				jw_ip(w,NULL,v+i+6+al+j);
			jw_end(w);
			p=v+i+6+al+xl;
			jw_arr(w,"svcparams");
			for (j=0;j<n-4-al-xl;j+=4+vl) {
				vl=(int)be16(p+j+2);
				json_svcparam(w,be16(p+j),p+j+4,vl);
			}
			jw_end(w);
		}
		jw_end(w);
	}
	jw_end(w);
} // }}}

static void json_value(struct jw *w,int code,const uint8_t *v,int len) { // {{{ the value of one option, typed by opt_info; malformed exactly when the text output says so
	const struct opt_info *oi=&opt_info[code];
	const char *why=opt_malformed(oi->type,v,len);
	int i;

	if (why) {
		jw_str(w,"malformed",why);
		jw_hex(w,"hex",v,len);
		return;
	}
	switch (oi->type) {
		default: // OT_TEXT; a zero length option (e.g. rapid commit) has no value at all
			if (len>0&&is_printable(v,len))
				jw_strn(w,"value",v,len);
			else if (len>0&&!json_allhex) // with -H the hex follows below anyway
				jw_hex(w,"hex",v,len);
			break;
		case OT_ADDR:
			jw_ip(w,"value",v);
			break;
		case OT_ADDRS:
			jw_arr(w,"value");
			for (i=0;i+4<=len;i+=4)
				jw_ip(w,NULL,v+i);
			jw_end(w);
			break;
		case OT_SLPDA:
			jw_obj(w,"value");
			jw_uint(w,"mandatory",v[0]);
			jw_arr(w,"addrs");
			for (i=1;i+4<=len;i+=4)
				jw_ip(w,NULL,v+i);
			jw_end(w);
			jw_end(w);
			break;
		case OT_ADDRMASKS:
		case OT_ROUTES:
			jw_arr(w,"value");
			for (i=0;i+8<=len;i+=8) {
				jw_obj(w,NULL);
				jw_ip(w,oi->type==OT_ADDRMASKS?"addr":"dest",v+i);
				jw_ip(w,oi->type==OT_ADDRMASKS?"mask":"router",v+i+4);
				jw_end(w);
			}
			jw_end(w);
			break;
		case OT_U8:
			jw_uint(w,"value",v[0]);
			break;
		case OT_U16:
			jw_uint(w,"value",be16(v));
			break;
		case OT_U16S:
			jw_arr(w,"value");
			for (i=0;i+2<=len;i+=2)
				jw_uint(w,NULL,be16(v+i));
			jw_end(w);
			break;
		case OT_SECS:
		case OT_EPOCH:
			jw_uint(w,"value",be32(v));
			break;
		case OT_TIMEOFFSET:
			jw_int(w,"value",be32s(v));
			break;
		case OT_ENUM:
			jw_uint(w,"value",v[0]);
			if (v[0]<oi->nnames&&oi->names[v[0]][0])
				jw_str(w,"text",oi->names[v[0]]);
			break;
		case OT_HEX:
			if (!json_allhex)
				jw_hex(w,"hex",v,len);
			break;
		case OT_PRL:
			jw_arr(w,"value");
			for (i=0;i<len;i++) {
				jw_obj(w,NULL);
				jw_uint(w,"code",v[i]);
				jw_str(w,"name",dhcp_options[v[i]]);
				jw_end(w);
			}
			jw_end(w);
			break;
		case OT_FQDN:
			jw_obj(w,"value");
			jw_uint(w,"flags",v[0]);
			jw_uint(w,"rcode1",v[1]);
			jw_uint(w,"rcode2",v[2]);
			if (len>3) { // the E flag makes the name DNS wire format, which fails the printable check
				if (is_printable(v+3,len-3))
					jw_strn(w,"name",v+3,len-3);
				else
					jw_hex(w,"name_hex",v+3,len-3);
			}
			jw_end(w);
			break;
		case OT_RELAY:
			jw_arr(w,"value");
			for (i=0;i<len;) {
				jw_obj(w,NULL);
				jw_uint(w,"code",v[i]);
				if (v[i]<strcountof(relayagent_suboptions))
					jw_str(w,"name",relayagent_suboptions[v[i]]);
				if (i+2>len) { // sub-option code and length must both be present
					jw_str(w,"malformed","truncated"); // only the code byte is left, already shown as code
					jw_end(w);
					break;
				}
				jw_uint(w,"len",v[i+1]);
				if (i+2+v[i+1]>len) {
					jw_str(w,"malformed","too large");
					jw_hex(w,"hex",v+i+2,len-i-2);
					jw_end(w);
					break;
				}
				if (v[i+1]>0&&is_printable(v+i+2,v[i+1]))
					jw_strn(w,"value",v+i+2,v[i+1]);
				else if (v[i+1]>0&&!json_allhex)
					jw_hex(w,"hex",v+i+2,v[i+1]);
				if (json_allhex)
					jw_hex(w,"hex",v+i+2,v[i+1]);
				jw_end(w);
				i+=v[i+1]+2;
			}
			jw_end(w);
			break;
		case OT_ARCH:
			jw_arr(w,"value");
			for (i=0;i+2<=len;i+=2) {
				unsigned a=be16(v+i);

				jw_obj(w,NULL);
				jw_uint(w,"value",a);
				if (a<strcountof(client_architecture_names))
					jw_str(w,"text",client_architecture_names[a]);
				jw_end(w);
			}
			jw_end(w);
			break;
		case OT_NDI:
			jw_obj(w,"value");
			jw_uint(w,"type",v[0]);
			jw_uint(w,"major",v[1]);
			jw_uint(w,"minor",v[2]);
			jw_end(w);
			break;
		case OT_CROUTES: // croutes_ok (via opt_malformed) guarantees every prefix is at most 32 bits and in bounds
			jw_arr(w,"value");
			for (i=0;i<len;) {
				int bits=v[i],sig=(bits+7)/8;
				uint8_t dest[4]={0,0,0,0};
				char b[24];

				memcpy(dest,v+i+1,sig);
				snprintf(b,sizeof b,"%u.%u.%u.%u/%d",dest[0],dest[1],dest[2],dest[3],bits);
				jw_obj(w,NULL);
				jw_str(w,"dest",b);
				jw_ip(w,"via",v+i+1+sig);
				jw_end(w);
				i+=1+sig+4;
			}
			jw_end(w);
			break;
		case OT_DNR:
			json_dnr(w,v,len);
			break;
	}
	if (json_allhex) // the exact bytes behind the decoded value (an over-long value keeps its extra bytes only here)
		jw_hex(w,"hex",v,len);
} // }}}

static void json_option_area(struct jw *w,const uint8_t *data,int data_len,const char *source) { // {{{ one TLV option area into the open options array, walked like print_option_area; pad and end are not listed
	int j=0;

	while (j<data_len&&data[j]!=255) {
		if (data[j]==0) {
			j++;
			continue;
		}
		jw_obj(w,NULL);
		jw_uint(w,"code",data[j]);
		jw_str(w,"name",dhcp_options[data[j]]);
		if (j+2>data_len||j+2+data[j+1]>data_len) { // length byte or part of the value not captured
			int vs=j+2<=data_len?j+2:data_len;

			if (j+2<=data_len)
				jw_uint(w,"len",data[j+1]);
			jw_str(w,"malformed","truncated");
			jw_hex(w,"hex",data+vs,data_len-vs);
			if (source)
				jw_str(w,"source",source);
			jw_end(w);
			break;
		}
		jw_uint(w,"len",data[j+1]);
		json_value(w,data[j],data+j+2,data[j+1]);
		if (source)
			jw_str(w,"source",source);
		jw_end(w);
		j+=data[j+1]+2;
	}
} // }}}

static void json_name_field(struct jw *w,const char *key,const uint8_t *p,int size,int overloaded) { // {{{ sname/file: text when printable, key_hex otherwise, null when it carries options instead
	int n=(int)strnlen((const char *)p,size);
	char hk[16];

	if (overloaded)
		jw_null(w,key);
	else if (is_printable(p,n))
		jw_strn(w,key,p,n);
	else {
		snprintf(hk,sizeof hk,"%s_hex",key);
		jw_hex(w,hk,p,n);
	}
} // }}}

static void json_bootp(struct jw *w,const uint8_t *d,int len) { // {{{ BOOTP header and options (caller ensures len>=DHCP_FIXED)
	int i,n,hl,overload=find_overload(d,len);
	char b[64];

	jw_uint(w,"op",d[0]);
	if (d[0]<strcountof(operands))
		jw_str(w,"op_text",operands[d[0]]);
	jw_uint(w,"htype",d[1]);
	if (d[1]<strcountof(htypes))
		jw_str(w,"htype_text",htypes[d[1]]);
	jw_uint(w,"hlen",d[2]);
	jw_uint(w,"hops",d[3]);
	snprintf(b,sizeof b,"%02x%02x%02x%02x",d[4],d[5],d[6],d[7]);
	jw_str(w,"xid",b);
	jw_uint(w,"secs",be16(d+8));
	jw_uint(w,"flags",be16(d+10));
	jw_ip(w,"ciaddr",d+12);
	jw_ip(w,"yiaddr",d+16);
	jw_ip(w,"siaddr",d+20);
	jw_ip(w,"giaddr",d+24);
	hl=d[2]==0||d[2]>16?16:d[2]; // hlen bytes of the 16 byte field are the address
	for (i=0,n=0;i<hl;i++)
		n+=snprintf(b+n,sizeof b-n,"%s%02x",i?":":"",d[28+i]);
	jw_str(w,"chaddr",b);
	json_name_field(w,"sname",d+44,64,overload&2);
	json_name_field(w,"file",d+108,128,overload&1);
	if (len<DHCP_FIXED+4||memcmp(d+DHCP_FIXED,dhcp_cookie,4)) { // plain BOOTP: vendor data, not options
		jw_hex(w,"vendor_hex",d+DHCP_FIXED,len-DHCP_FIXED);
		return;
	}
	jw_arr(w,"options");
	json_option_area(w,d+DHCP_FIXED+4,len-DHCP_FIXED-4,NULL);
	if (overload&1) // the file field's options, then sname's, in RFC 3396 order
		json_option_area(w,d+108,128,"file");
	if (overload&2)
		json_option_area(w,d+44,64,"sname");
	jw_end(w);
} // }}}

void ts_normalize(struct timeval *tv) { // {{{
	long q,r;

	if (tv->tv_usec>=0&&tv->tv_usec<=999999)
		return;
	q=(long)tv->tv_usec/1000000;
	r=(long)tv->tv_usec%1000000;
	if (r<0) { // division truncates toward zero; borrow a second so the microseconds end up in range
		r+=1000000;
		q--;
	}
	tv->tv_sec+=q;
	tv->tv_usec=r;
} // }}}

static void json_time(struct jw *w,const struct timeval *ts) { // {{{ ts as epoch seconds, time as local ISO 8601 with offset (null when the instant is not a representable date); ts is normalized
	long usec=(long)ts->tv_usec;
	time_t t=ts->tv_sec;
	struct tm tm;
	char b[64],z[8];

	jw_num(w,"ts",(long long)ts->tv_sec,(unsigned long)usec,6);
	if (localtime_r(&t,&tm)&&strftime(b,sizeof b,"%Y-%m-%dT%H:%M:%S",&tm)&&strftime(z,sizeof z,"%z",&tm)==5) {
		snprintf(b+strlen(b),sizeof b-strlen(b),".%03ld%.3s:%s",usec/1000,z,z+3);
		jw_str(w,"time",b);
	} else
		jw_null(w,"time");
} // }}}

void dhcp_json_print(FILE *out,const struct dhcp_frame *f,const struct timeval *ts,const uint8_t *frame,int framelen) { // {{{ one packet as a single JSON line (the -j output)
	uint8_t ip[4];
	char b[24];
	struct jw w;
	int i;

	if (f->plen==0) // UDP with no payload at all: nothing to show, as in the text output
		return;

	json_allhex=frame!=NULL;
	jw_init(&w,out);
	jw_obj(&w,NULL);
	jw_uint(&w,"schema",1);
	json_time(&w,ts);
	if (f->nvlan) {
		jw_arr(&w,"vlan");
		for (i=0;i<f->nvlan;i++) {
			b[0]=f->vlan[i].type;
			b[1]=0;
			jw_obj(&w,NULL);
			jw_str(&w,"type",b);
			jw_uint(&w,"id",f->vlan[i].id);
			jw_end(&w);
		}
		jw_end(&w);
	}
	jw_obj(&w,"src");
	memcpy(ip,&f->srcip,4);
	jw_ip(&w,"ip",ip);
	snprintf(b,sizeof b,"%02x:%02x:%02x:%02x:%02x:%02x",f->smac[0],f->smac[1],f->smac[2],f->smac[3],f->smac[4],f->smac[5]);
	jw_str(&w,"mac",b);
	jw_end(&w);
	jw_obj(&w,"dst");
	memcpy(ip,&f->dstip,4);
	jw_ip(&w,"ip",ip);
	snprintf(b,sizeof b,"%02x:%02x:%02x:%02x:%02x:%02x",f->dmac[0],f->dmac[1],f->dmac[2],f->dmac[3],f->dmac[4],f->dmac[5]);
	jw_str(&w,"mac",b);
	jw_end(&w);
	jw_uint(&w,"len",(unsigned long)f->plen);
	if (f->plen<DHCP_FIXED) // too short for the fixed BOOTP header
		jw_true(&w,"truncated");
	else
		json_bootp(&w,f->payload,f->plen);
	if (frame)
		jw_hex(&w,"frame_hex",frame,framelen>0?(size_t)framelen:0);
	jw_end(&w);
	fputc('\n',out);
	fflush(out);
} // }}}

// }}}
