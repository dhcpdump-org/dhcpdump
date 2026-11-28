// Write the test captures into the directory given as the only argument.
//
// options.pcap  every option code with a fixed set of values that hit each
//               type's valid, malformed and too short paths
// frames.pcap   structured options, truncation, header and framing special
//               cases (both are decoded and compared against tests/expected)
// fuzz.pcap     pseudo-random option areas and frames; only checked for a
//               clean exit and valid JSON
//
// Everything is deterministic (own LCG, fixed timestamps), so the same
// program always writes the same bytes.

// {{{ includes

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// }}}

// {{{ definitions

#define TS0 1700000000u
#define BUFSZ 2048

#define L(s) (const uint8_t *)(s),sizeof (s)-1 // a string literal as bytes and length, without its NUL

struct buf {
	uint8_t d[BUFSZ];
	size_t n;
};

struct vlan {
	unsigned tpid,vid;
};

static const uint8_t chaddr_default[6]={0x00,0xc0,0x4f,0x82,0xac,0x7f};
static const uint8_t ip_any[4]={0,0,0,0};
static const uint8_t ip_bcast[4]={255,255,255,255};
static const uint8_t mac_bcast[6]={255,255,255,255,255,255};

static FILE *out;
static unsigned npkt;

// }}}

static void put(struct buf *b,const uint8_t *p,size_t n) { // {{{ append bytes; the captures are small and fixed, running out of room is a bug here
	if (b->n+n>BUFSZ) {
		fprintf(stderr,"mkpcap: buffer overflow\n");
		exit(1);
	}
	if (n)
		memcpy(b->d+b->n,p,n);
	b->n+=n;
} // }}}

static void put8(struct buf *b,unsigned v) { // {{{
	uint8_t c=(uint8_t)v;

	put(b,&c,1);
} // }}}

static void put16(struct buf *b,unsigned v) { // {{{ network order
	put8(b,v>>8);
	put8(b,v&0xff);
} // }}}

static void put32(struct buf *b,uint32_t v) { // {{{ network order
	put16(b,v>>16);
	put16(b,v&0xffff);
} // }}}

static void putzero(struct buf *b,size_t n) { // {{{
	while (n--)
		put8(b,0);
} // }}}

static void opt(struct buf *b,unsigned code,const uint8_t *v,size_t n) { // {{{ one TLV option
	put8(b,code);
	put8(b,(unsigned)n);
	put(b,v,n);
} // }}}

static void field(struct buf *b,const uint8_t *p,size_t n,size_t size) { // {{{ a fixed size field, zero padded, cut at size
	if (n>size)
		n=size;
	put(b,p,n);
	putzero(b,size-n);
} // }}}

static void bootp(struct buf *b,const struct buf *options,unsigned op,unsigned hlen,const uint8_t *chaddr,size_t chlen,const struct buf *sname,const struct buf *file,int cookie,unsigned flags,const uint8_t *yiaddr) { // {{{ BOOTP header, magic cookie and options
	static const uint8_t magic[4]={0x63,0x82,0x53,0x63};

	b->n=0;
	put8(b,op);
	put8(b,1);
	put8(b,hlen);
	put8(b,0);
	put32(b,0x3903f326u);
	put16(b,3);
	put16(b,flags);
	put(b,ip_any,4);
	put(b,yiaddr,4);
	put(b,ip_any,4);
	put(b,ip_any,4);
	field(b,chaddr,chlen,16);
	field(b,sname?sname->d:NULL,sname?sname->n:0,64);
	field(b,file?file->d:NULL,file?file->n:0,128);
	if (cookie)
		put(b,magic,4);
	put(b,options->d,options->n);
} // }}}

static void request(struct buf *b,const struct buf *options) { // {{{ the common case: a broadcast request from the default client
	bootp(b,options,1,6,chaddr_default,6,NULL,NULL,1,0x8000,ip_any);
} // }}}

static void frame(const struct buf *payload,unsigned sport,unsigned dport,const struct vlan *vl,int nvl,const uint8_t *src,uint32_t usec) { // {{{ wrap a payload in UDP, IPv4 and Ethernet and write it as one pcap record
	struct buf f;
	uint8_t h[16];
	uint32_t sum,v[4];
	size_t ipoff,i;
	int k;

	f.n=0;
	put(&f,mac_bcast,6);
	put(&f,chaddr_default,6);
	for (k=0;k<nvl;k++) {
		put16(&f,vl[k].tpid);
		put16(&f,vl[k].vid);
	}
	put16(&f,0x0800);
	ipoff=f.n;
	put8(&f,0x45);
	put8(&f,0);
	put16(&f,(unsigned)(20+8+payload->n));
	put16(&f,1);
	put16(&f,0);
	put8(&f,64);
	put8(&f,17);
	put16(&f,0);
	put(&f,src,4);
	put(&f,ip_bcast,4);
	for (sum=0,i=0;i<20;i+=2)
		sum+=((uint32_t)f.d[ipoff+i]<<8)|f.d[ipoff+i+1];
	sum=(sum>>16)+(sum&0xffff);
	sum+=sum>>16;
	sum=~sum&0xffff;
	f.d[ipoff+10]=(uint8_t)(sum>>8);
	f.d[ipoff+11]=(uint8_t)(sum&0xff);
	put16(&f,sport);
	put16(&f,dport);
	put16(&f,(unsigned)(8+payload->n));
	put16(&f,0);
	put(&f,payload->d,payload->n);

	v[0]=TS0+npkt++;
	v[1]=usec;
	v[2]=(uint32_t)f.n;
	v[3]=(uint32_t)f.n;
	for (k=0;k<16;k++) // pcap records are little endian here, matching the file header's magic
		h[k]=(uint8_t)(v[k/4]>>(8*(k%4)));
	fwrite(h,1,16,out);
	fwrite(f.d,1,f.n,out);
} // }}}

static void plain(const struct buf *payload) { // {{{ the common case: client to server, untagged
	frame(payload,68,67,NULL,0,ip_any,0);
} // }}}

static void pcap_open(const char *dir,const char *name) { // {{{ start a capture file with a classic microsecond pcap header
	static const uint8_t hdr[24]={
		0xd4,0xc3,0xb2,0xa1, 2,0, 4,0, 0,0,0,0, 0,0,0,0, 0xff,0xff,0,0, 1,0,0,0,
	};
	char path[4096];

	snprintf(path,sizeof path,"%s/%s",dir,name);
	out=fopen(path,"wb");
	if (!out) {
		perror(path);
		exit(1);
	}
	fwrite(hdr,1,sizeof hdr,out);
	npkt=0;
} // }}}

static void pcap_close(void) { // {{{
	if (fclose(out)) {
		perror("mkpcap");
		exit(1);
	}
} // }}}

static void options(const char *dir) { // {{{ every option code, each with the same set of values
	static const struct {
		const uint8_t *v;
		size_t n;
	} values[]={
		{L("")},
		{L("\x01")},
		{L("\x05\xdc")},
		{L("\x01\x02\x03")},
		{L("\x0a\x00\x00\x01")},
		{L("\x01\x0a\x00\x00\x01")},
		{L("\x0a\x00\x00\x00\xff\xff\xff\x00")},
		{L("\x01\x0a\x00\x00\x01\x0a\x00\x00\x02")},
		{L("\xff\xff\xb9\xb0")},
		{L("\x80\x00\x00\x00")},
		{L("dhcpdump-test")},
		{L("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")},
	};
	struct buf o,p;
	unsigned code;
	size_t i;

	pcap_open(dir,"options.pcap");
	for (code=1;code<255;code++) {
		o.n=0;
		opt(&o,53,L("\x01"));
		for (i=0;i<sizeof values/sizeof *values;i++)
			opt(&o,code,values[i].v,values[i].n);
		put8(&o,255);
		request(&p,&o);
		plain(&p);
	}
	pcap_close();
} // }}}

static void dnr(struct buf *o,const uint8_t *svc,size_t n) { // {{{ option 162 holding one full DNR instance (priority 1, dns.example, 192.0.2.53) with the given SvcParams
	struct buf t;

	t.n=0;
	put16(&t,(unsigned)(2+1+13+1+4+n));
	put16(&t,1);
	put8(&t,13);
	put(&t,L("\x03" "dns" "\x07" "example" "\x00"));
	put8(&t,4);
	put(&t,L("\xc0\x00\x02\x35"));
	put(&t,svc,n);
	opt(o,162,t.d,t.n);
} // }}}

static void frames(const char *dir) { // {{{ structured options and header/framing special cases
	static const uint8_t prl[]={1,3,6,15,31,33,43,44,46,47,119,121,249,252,0,255};
	static const uint8_t chaddr16[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	static const uint8_t srv[4]={10,0,0,1};
	static const uint8_t yi[4]={10,0,0,100};
	struct buf o,p,t,sname,file;
	struct vlan vl[2];
	int i;

	pcap_open(dir,"frames.pcap");

	// relay agent information: printable, binary, unknown, too large, truncated
	t.n=0;
	opt(&t,1,L("eth0:100"));
	opt(&t,2,chaddr_default,6);
	opt(&t,5,L("\x0a\x00\x00\x01"));
	opt(&t,9,L("\x00\x00\x0d\xe9\x05\x01\x03" "abc"));
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,82,t.d,t.n);
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	t.n=0;
	opt(&t,1,L("x"));
	put(&t,L("\x02\x09\x01"));
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,82,t.d,t.n);
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	t.n=0;
	opt(&t,1,L("x"));
	put8(&t,2);
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,82,t.d,t.n);
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,82,L(""));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	// classless static routes: default, /24, /32, /0 and a bad prefix length
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,121,L("\x00\x0a\x00\x00\x01" "\x18\xc0\xa8\x01\x0a\x00\x00\x02" "\x20\x0a\x01\x02\x03\x0a\x00\x00\x03"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,121,L("\x21\x0a\x00\x00\x00\x00\x0a\x00\x00\x01"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,249,L("\x18\xc0\xa8\x01\x0a\x00"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	// parameter request list, FQDN with a plain and a wire format name, PXE
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,55,prl,sizeof prl);
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,81,L("\x01\x00\x00" "host.example.com"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,81,L("\x05\x00\x00\x04" "host" "\x07" "example" "\x03" "com" "\x00"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,93,L("\x00\x00\x00\x07\x00\x10\xff\xff"));
	opt(&o,94,L("\x01\x02\x01"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	// a client id, and a host name carrying a terminal escape
	t.n=0;
	put8(&t,1);
	put(&t,chaddr_default,6);
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,61,t.d,t.n);
	opt(&o,12,L("host\x1b[2Jname"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	// long printable value that wraps
	t.n=0;
	for (i=0;i<20;i++)
		put(&t,L("MSFT 5.0 "));
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,60,t.d,t.n);
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	// no end option, pad bytes, a value cut off, a lone code byte at the end, data after the end
	o.n=0;
	opt(&o,53,L("\x05"));
	put(&o,L("\x00\x00"));
	opt(&o,12,L("abc"));
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	put(&o,L("\x0c\x08" "abc"));
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	put8(&o,12);
	request(&p,&o);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x05"));
	put8(&o,255);
	put(&o,L("\x0c\x03" "abc"));
	request(&p,&o);
	plain(&p);

	// overloaded file and sname fields carry options (RFC 2132 9.3)
	file.n=0;
	opt(&file,12,L("in-file"));
	put8(&file,255);
	sname.n=0;
	opt(&sname,15,L("in.sname"));
	put8(&sname,255);
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,52,L("\x03"));
	put8(&o,255);
	bootp(&p,&o,1,6,chaddr_default,6,&sname,&file,1,0x8000,ip_any);
	plain(&p);

	sname.n=0;
	put(&sname,L("server.example"));
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,52,L("\x01"));
	put8(&o,255);
	bootp(&p,&o,1,6,chaddr_default,6,&sname,&file,1,0x8000,ip_any);
	plain(&p);

	// binary sname and printable file, BOOTP without the cookie, a reply
	sname.n=0;
	put(&sname,L("boot\x01srv"));
	file.n=0;
	put(&file,L("pxelinux.0"));
	o.n=0;
	opt(&o,53,L("\x05"));
	put8(&o,255);
	bootp(&p,&o,1,6,chaddr_default,6,&sname,&file,1,0x8000,ip_any);
	plain(&p);

	o.n=0;
	putzero(&o,64);
	bootp(&p,&o,1,6,chaddr_default,6,NULL,NULL,0,0x8000,ip_any);
	plain(&p);

	o.n=0;
	opt(&o,53,L("\x02"));
	opt(&o,54,srv,4);
	put8(&o,255);
	bootp(&p,&o,2,6,chaddr_default,6,NULL,NULL,1,0,yi);
	frame(&p,67,68,NULL,0,srv,0);

	// odd hardware address lengths
	o.n=0;
	opt(&o,53,L("\x05"));
	put8(&o,255);
	bootp(&p,&o,1,0,chaddr_default,6,NULL,NULL,1,0x8000,ip_any);
	plain(&p);
	bootp(&p,&o,1,20,chaddr16,16,NULL,NULL,1,0x8000,ip_any);
	plain(&p);

	// payload shorter than the BOOTP header, empty payload
	o.n=0;
	opt(&o,53,L("\x05"));
	request(&p,&o);
	p.n=100;
	plain(&p);
	p.n=0;
	plain(&p);

	// 802.1Q and QinQ
	o.n=0;
	opt(&o,53,L("\x05"));
	put8(&o,255);
	request(&p,&o);
	vl[0].tpid=0x8100;
	vl[0].vid=100;
	frame(&p,68,67,vl,1,ip_any,0);
	vl[0].tpid=0x88a8;
	vl[0].vid=10;
	vl[1].tpid=0x8100;
	vl[1].vid=20;
	frame(&p,68,67,vl,2,ip_any,0);

	// a microsecond count out of range is folded into the seconds
	frame(&p,68,67,NULL,0,ip_any,2500000);

	// encrypted DNS service parameters: mandatory valid, naming a missing key, holding
	// itself, out of order; address hints (not allowed); empty dohpath, ech and unknown
	// key; an alpn id with a comma; dohpath and ech with values
	o.n=0;
	opt(&o,53,L("\x05"));
	dnr(&o,L("\x00\x00\x00\x04\x00\x01\x00\x03" "\x00\x01\x00\x06\x02" "h2" "\x02" "h3" "\x00\x03\x00\x02\x01\xbb"));
	dnr(&o,L("\x00\x00\x00\x02\x00\x07" "\x00\x01\x00\x03\x02" "h2"));
	dnr(&o,L("\x00\x00\x00\x02\x00\x00" "\x00\x01\x00\x03\x02" "h2"));
	dnr(&o,L("\x00\x00\x00\x04\x00\x03\x00\x01" "\x00\x01\x00\x03\x02" "h2" "\x00\x03\x00\x02\x01\xbb"));
	dnr(&o,L("\x00\x04\x00\x04\xc0\x00\x02\x01"));
	dnr(&o,L("\x00\x07\x00\x00"));
	dnr(&o,L("\x00\x05\x00\x00"));
	dnr(&o,L("\x00\x2a\x00\x00"));
	dnr(&o,L("\x00\x01\x00\x04\x03" "a,b"));
	dnr(&o,L("\x00\x05\x00\x03\x01\x02\x03" "\x00\x07\x00\x10" "/dns-query{?dns}"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	// encrypted DNS (RFC 9463): a full instance with alpn and port, then an ADN-only one
	o.n=0;
	opt(&o,53,L("\x05"));
	opt(&o,162,L("\x00\x22" "\x00\x01" "\x0d" "\x03" "dns" "\x07" "example" "\x00" "\x04" "\xc0\x00\x02\x35"
		"\x00\x01\x00\x03" "\x02" "h2" "\x00\x03\x00\x02\x01\xbb"
		"\x00\x10" "\x00\x02" "\x0d" "\x03" "dns" "\x07" "example" "\x00"));
	put8(&o,255);
	request(&p,&o);
	plain(&p);

	pcap_close();
} // }}}

static uint64_t lcg=1;

static uint32_t rnd(uint32_t n) { // {{{ 64 bit LCG (Knuth MMIX constants), high bits, reduced to [0,n)
	lcg=lcg*6364136223846793005u+1442695040888963407u;
	return (uint32_t)((lcg>>33)%n);
} // }}}

static void rndbytes(struct buf *b,size_t n) { // {{{
	while (n--)
		put8(b,rnd(256));
} // }}}

static void fuzz(const char *dir) { // {{{ pseudo-random option areas, overloads, header lengths and truncation
	struct buf o,p,sname,file;
	uint32_t k,nopt,n,op,hlen,usec;
	int overload;

	pcap_open(dir,"fuzz.pcap");
	for (k=0;k<2000;k++) {
		o.n=0;
		if (rnd(2)) {
			put8(&o,53);
			put8(&o,1);
			put8(&o,1+rnd(8));
		}
		for (nopt=rnd(8);nopt;nopt--) {
			n=rnd(24);
			put8(&o,1+rnd(254));
			put8(&o,n);
			rndbytes(&o,n);
		}
		if (rnd(10)<3)
			o.n=rnd((uint32_t)o.n+1);
		if (rnd(10)<8)
			put8(&o,255);
		sname.n=file.n=0;
		overload=rnd(10)==0;
		if (overload) {
			memmove(o.d+3,o.d,o.n);
			o.d[0]=52;
			o.d[1]=1;
			o.d[2]=(uint8_t)(1+rnd(3));
			o.n+=3;
			rndbytes(&sname,64);
			rndbytes(&file,128);
		}
		op=1+rnd(2);
		hlen=rnd(20);
		bootp(&p,&o,op,hlen,chaddr_default,6,&sname,&file,1,0x8000,ip_any);
		if (rnd(20)==0)
			p.n=rnd((uint32_t)p.n+1);
		usec=rnd(1000000);
		frame(&p,68,67,NULL,0,ip_any,usec);
	}
	pcap_close();
} // }}}

int main(int argc,char **argv) { // {{{
	if (argc!=2) {
		fprintf(stderr,"usage: %s <output directory>\n",argv[0]);
		return 1;
	}
	options(argv[1]);
	frames(argv[1]);
	fuzz(argv[1]);
	return 0;
} // }}}
