// {{{ includes

#include <err.h>
#include <pcap.h>
#include <time.h>
#include <regex.h>
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "dhcp.h"
#include "version.h"
#include "session.h"
#include "dhcpdump.h"

// }}}

// {{{ definitions

#define LARGESTRING 1024

// DHCP-over-IPv4/UDP predicate; "ip" keeps IPv6 out. Matched bare and below one
// or two VLAN tags, so untagged, single-tagged and QinQ DHCP are all captured.
// Each "vlan" keyword shifts the decode offset by one tag for the rest of the
// expression, and that shift leaks rightward across "or"; a flat list of
// alternatives therefore mis-decodes. The deeper level must be *nested* inside
// the previous "vlan" group so each shift stays scoped to its own subexpression.
#define DHCPFILTER "ip and udp and (src port bootpc or bootps) and (dst port bootpc or bootps)"
#define CAPFILTER "(" DHCPFILTER ") or (vlan and ((" DHCPFILTER ") or (vlan and (" DHCPFILTER "))))"

// }}}

// {{{ globals

char errbuf[PCAP_ERRBUF_SIZE];
char *hmask=NULL; // -h, MAC address filter regexp (NULL if unset)
regex_t preg; // compiled hmask
int dohexdump=0; // -H, dump whole packet contents for debug
int tuimode=0; // -t, track sessions instead of dumping each packet
pcap_t *cap=NULL; // capture handle (file scope so the signal handler can stop it)
struct sess_model model; // session tracker, used in -t mode

// }}}

static void on_stop(int sig __attribute__((unused))) { // {{{ break out of pcap_loop on SIGINT/SIGTERM
	if (cap)
		pcap_breakloop(cap);
} // }}}

static inline int usage(const char *me) { // {{{
	printf("dhcpdump "VERSION"\n");
	printf("  Usage:\n");
	printf("    %s -i <interface> [-h <macaddress>] [-H]\n",me);
	printf("    %s -r <pcapfile>  [-h <macaddress>] [-H]\n",me);
	printf("  Options:\n");
	printf("    -h regexp filter by <macaddress>\n");
	printf("    -H prints whole packet hex dump\n");
	printf("    -t track DHCP sessions and their transactions\n");
	return 0;
} // }}}

static inline int check_ch(const uint8_t *data,int data_len) { // {{{ check for matching CHADDR (Peter Apian-Bennewitz <apian@ise.fhg.de>)
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

static void pcap_callback(uint8_t *user __attribute__((unused)),const struct pcap_pkthdr *h,const uint8_t *sp) { // {{{
	struct dhcp_frame f;
	char timestamp[40];
	struct timeval tp;

	if (dohexdump&&!tuimode) {
		dhcp_hexdump(sp,h->caplen);
		printf("\n");
	}

	if (!dhcp_decap(sp,h->caplen,&f,tuimode?NULL:stderr))
		return;

	if (hmask&&check_ch(f.payload,f.plen))
		return;

	if (tuimode) { // feed the session tracker; use the captured time, not wall clock
		struct dhcp_msg m;

		if (dhcp_parse(f.payload,f.plen,&m)) {
			m.ts=h->ts;
			m.srcip=ntohl(f.srcip);
			m.dstip=ntohl(f.dstip);
			sess_ingest(&model,&m);
		}
		return;
	}

	gettimeofday(&tp,NULL);
	strftime(timestamp,sizeof timestamp,"%Y-%m-%d %H:%M:%S.",localtime(&(tp.tv_sec)));
	snprintf(timestamp+strlen(timestamp),sizeof timestamp-strlen(timestamp),"%03ld",tp.tv_usec/1000);

	dhcp_print(&f,timestamp);
} // }}}

int main(int argc,char **argv) { // {{{
	struct bpf_program fp;
	char *interface=NULL;
	char *pcapfile=NULL;
	int i;

	for (i=1;i<argc;i++) {
		char **dst=NULL;

		if (argv[i]==NULL||argv[i][0]!='-')
			break;
		switch (argv[i][1]) {
			case 'H':
				dohexdump=1;
				break;
			case 't':
				tuimode=1;
				break;
			case 'h':
				dst=&hmask;
				break;
			case 'i':
				dst=&interface;
				break;
			case 'r':
				dst=&pcapfile;
				break;
			default:
				fprintf(stderr,"%s: %c: unknown option\n",argv[0],argv[i][1]);
				return usage(argv[0]);
		}
		if (dst) { // -h/-i/-r consume the following argument, which must exist
			if (i+1>=argc) {
				fprintf(stderr,"%s: -%c: option requires an argument\n",argv[0],argv[i][1]);
				return usage(argv[0]);
			}
			*dst=argv[++i];
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
	if (pcap_compile(cap,&fp,CAPFILTER,0,0)<0)
		errx(1,"pcap_compile: %s",pcap_geterr(cap));
	if (pcap_setfilter(cap,&fp)<0)
		errx(1,"pcap_setfilter: %s",pcap_geterr(cap));
	pcap_freecode(&fp);

	if (tuimode) {
		sess_model_init(&model,SESS_TIMEOUT_MS);
		signal(SIGINT,on_stop); // let ^C end a live capture and print the summary
		signal(SIGTERM,on_stop);
	}

	// pcap_loop returns 0 at EOF (offline) and -2 on pcap_breakloop (our stop);
	// only -1 is a real error.
	if (pcap_loop(cap,0,pcap_callback,NULL)==-1)
		errx(1,"pcap_loop(%s): %s",interface?interface:pcapfile,pcap_geterr(cap));

	if (tuimode) {
		sess_dump(&model,stdout);
		sess_model_free(&model);
	}

	pcap_close(cap);

	return 0;
} // }}}
