// {{{ includes

#include <err.h>
#include <pwd.h>
#include <grp.h>
#include <pcap.h>
#include <time.h>
#include <regex.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "version.h"
#include "dhcpdump.h"
#ifndef NO_TUI
#include "tui.h"
#include "session.h"
#endif

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

#ifdef NO_TUI // built without the -t TUI (see NO_TUI in the Makefile)
#define TUIOPT ""
#else
#define TUIOPT " [-t]"
#endif

// }}}

// {{{ globals

char errbuf[PCAP_ERRBUF_SIZE];
char *hmask=NULL; // -h, MAC address filter regexp (NULL if unset)
regex_t preg; // compiled hmask
char *dropuser=NULL; // -Z, user to drop privileges to once the capture is open
int dohexdump=0; // -H, dump whole packet contents for debug
int tuimode=0; // -t, track sessions in the interactive TUI

// }}}

static inline int usage(const char *me) { // {{{ printed only on errors: stderr, and make the exit status say error too
	fprintf(stderr,"dhcpdump "VERSION"\n");
	fprintf(stderr,"  Usage:\n");
	fprintf(stderr,"    %s -i <interface> [-h <macaddress>] [-H] [-Z <user>]" TUIOPT "\n",me);
	fprintf(stderr,"    %s -r <pcapfile>  [-h <macaddress>] [-H] [-Z <user>]" TUIOPT "\n",me);
	fprintf(stderr,"  Options:\n");
	fprintf(stderr,"    -h regexp filter by <macaddress>\n");
	fprintf(stderr,"    -H prints whole packet hex dump\n");
	fprintf(stderr,"    -Z drop privileges to <user> once the capture is open\n");
#ifndef NO_TUI
	fprintf(stderr,"    -t track DHCP sessions and their transactions\n");
#endif
	return 1;
} // }}}

static void drop_privs(const char *user) { // {{{ irrevocably become user; everything past this point parses hostile input and has no reason to be root
	struct passwd *pw=getpwnam(user);

	if (!pw)
		errx(1,"-Z: no such user \"%s\"",user);
	if (geteuid()) { // unprivileged already: nothing to give up, but the promise still has to hold
		if (geteuid()!=pw->pw_uid)
			errx(1,"-Z: not privileged enough to become \"%s\"",user);
		return;
	}
	if (setgroups(1,&pw->pw_gid)<0) // supplementary groups first, they need the privileges being dropped
		err(1,"-Z: setgroups");
	if (setgid(pw->pw_gid)<0) // gid before uid, the other order cannot be undone
		err(1,"-Z: setgid");
	if (setuid(pw->pw_uid)<0)
		err(1,"-Z: setuid");
	if (pw->pw_uid&&setuid(0)!=-1) // regaining root must be impossible now
		errx(1,"-Z: privileges were not dropped");
} // }}}

static inline int check_ch(const uint8_t *data,int data_len) { // {{{ check for matching CHADDR (Peter Apian-Bennewitz <apian@ise.fhg.de>); returns 0 on match, like regexec
	char ch_ip[50];

	if (data_len<44) // CHADDR spans data[28..43]; without it there is nothing to match, so it cannot match
		return REG_NOMATCH;

	sprintf(ch_ip,
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		data[28],data[29],data[30],data[31],
		data[32],data[33],data[34],data[35],
		data[36],data[37],data[38],data[39],
		data[40],data[41],data[42],data[43]);

	return regexec(&preg,ch_ip,0,NULL,0);
} // }}}

#ifndef NO_TUI
static int tui_keep(const uint8_t *data,int data_len) { // {{{ TUI ingest filter: keep only packets passing the -h mask
	return !(hmask&&check_ch(data,data_len));
} // }}}
#endif

static void pcap_callback(uint8_t *user __attribute__((unused)),const struct pcap_pkthdr *h,const uint8_t *sp) { // {{{ classic per-packet line dump
	struct dhcp_frame f;
	char timestamp[40];

	if (dohexdump) {
		dhcp_hexdump(sp,h->caplen);
		printf("\n");
	}

	if (!dhcp_decap(sp,h->caplen,&f,stderr))
		return;

	if (hmask&&check_ch(f.payload,f.plen))
		return;

	// the capture time, not the wall clock: a replayed file (-r) shows when
	// its packets actually happened, and live captures stamp the same way
	strftime(timestamp,sizeof timestamp,"%Y-%m-%d %H:%M:%S.",localtime(&h->ts.tv_sec));
	snprintf(timestamp+strlen(timestamp),sizeof timestamp-strlen(timestamp),"%03ld",(long)h->ts.tv_usec/1000);

	dhcp_print(&f,timestamp);
} // }}}

int main(int argc,char **argv) { // {{{
	struct bpf_program fp;
	char *interface=NULL;
	char *pcapfile=NULL;
	pcap_t *cap;
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
#ifndef NO_TUI
				tuimode=1;
				break;
#else
				fprintf(stderr,"%s: built without TUI support (-t)\n",argv[0]);
				return usage(argv[0]);
#endif
			case 'h':
				dst=&hmask;
				break;
			case 'i':
				dst=&interface;
				break;
			case 'r':
				dst=&pcapfile;
				break;
			case 'Z':
				dst=&dropuser;
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
		// snaplen counts from the link layer, so the Ethernet and VLAN headers
		// would push a full-MTU DHCP message past a 1500 byte snaplen and cut
		// its tail; 65535 covers any frame and costs nothing since libpcap 1.5
		if ((cap=pcap_open_live(interface,65535,1,100,errbuf))==NULL)
			errx(1,"pcap_open_live(): %s",errbuf);
	} else {
		if ((cap=pcap_open_offline(pcapfile,errbuf))==NULL)
			errx(1,"pcap_open_offline(): %s",errbuf);
	}
	if (pcap_datalink(cap)!=DLT_EN10MB) { // dhcp_decap parses Ethernet framing only
		const char *dn=pcap_datalink_val_to_name(pcap_datalink(cap));

		errx(1,"%s: link type %s is not Ethernet%s",
			interface?interface:pcapfile,dn?dn:"*unknown*",
			interface?" (-i any captures in cooked framing, use a specific interface)":"");
	}
	if (pcap_compile(cap,&fp,CAPFILTER,1,0)<0) // optimize: the nested VLAN filter is 236 insns unoptimized, 45 optimized
		errx(1,"pcap_compile: %s",pcap_geterr(cap));
	if (pcap_setfilter(cap,&fp)<0)
		errx(1,"pcap_setfilter: %s",pcap_geterr(cap));
	pcap_freecode(&fp);

	if (dropuser) // the capture handle is open, nothing below needs privileges
		drop_privs(dropuser);

#ifndef NO_TUI
	if (tuimode) {
		struct sess_model model;
		int rc;

		sess_model_init(&model,SESS_TIMEOUT_MS);
		rc=tui_run(cap,&model,interface!=NULL,tui_keep);
		sess_model_free(&model);
		if (rc<0) // e.g. a live capture that died; the error is already on stderr
			return 1;
	} else
#endif
	if (pcap_loop(cap,0,pcap_callback,NULL)==-1) // offline EOF returns 0, only -1 is an error
		errx(1,"pcap_loop(%s): %s",interface?interface:pcapfile,pcap_geterr(cap));

	pcap_close(cap);

	return 0;
} // }}}
