// {{{ includes

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // wcwidth (XSI), and keep the BSD/misc types visible below
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <wchar.h>
#include <locale.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <langinfo.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include <yascreen.h>

#include "dhcp.h"
#include "version.h"
#include "session.h"
#include "dhcpdump.h"
#include "tui.h"

// }}}

// {{{ globals

enum { LAYOUT_VSPLIT,LAYOUT_HSPLIT }; // side by side / top and bottom

static yascreen *scr=NULL;
static volatile sig_atomic_t f_winch=1; // pending resize (1 forces initial layout)
static volatile sig_atomic_t f_stop=0; // quit requested
static volatile sig_atomic_t f_tstp=0; // suspend requested (Ctrl-Z key or external SIGTSTP)
static volatile sig_atomic_t f_cont=0; // resumed after a suspend
enum { FOCUS_LIST,FOCUS_DETAIL }; // which pane the keyboard drives

static int layout=LAYOUT_HSPLIT; // current split, toggled with v/V
static int focus=FOCUS_LIST; // active pane
static int help_active=0; // help dialog is shown
static int detail_top=0; // first row shown in the detail pane (line scroll)
static int detail_h=0; // detail pane height as last drawn (0 when the pane is not on screen)

// the message selected in the detail pane; also the packet shown in the overlay.
// tracked by pointer so it stays put as new packets shift indices around it.
static struct sess_msg *sel_msg=NULL;

// full-screen packet detail view (Enter from the detail pane)
static int ov_active=0; // packet view is open
static int ov_pkt=0; // index of sel_msg within ov_list
static int ov_scroll=0; // vertical scroll offset inside the decoded packet
static int ov_hscroll=0; // horizontal scroll offset (only when too wide to center)
static struct sess_msg *ov_list[SESS_MAX_TX*SESS_MAX_MSG]; // flattened packet list
static int ov_n=0;

// optional ingest filter: keep the packet only if this returns non-zero
static int (*g_keep)(const uint8_t *payload,int plen)=NULL;

// The selected client is remembered by hardware address, not by row index, so
// the selection stays anchored to its client even when eviction reindexes the list.
static uint8_t sel_mac[16];
static uint8_t sel_hlen;
static uint8_t sel_htype;
static int sel_valid=0;

// detail pane rows, rebuilt each frame: client header, summary, then per
// transaction a header line and one selectable row per message
struct drow { uint32_t attr; struct sess_msg *msg; char text[256]; };
static struct drow drows[3+SESS_MAX_TX*(1+SESS_MAX_MSG)];
static int ndrows=0;

static void ov_build(struct sess *s); // flatten a client's packets into ov_list (defined below)

#define MACSTR (16*3) // "xx:" per byte of a 16 byte chaddr, the last colon making room for the NUL

// glyphs: box-drawing in UTF-8 terminals, plain ASCII otherwise (toggle with u/a)
static int unicode=0;
#define MARK (unicode?"▶":">") // selection marker
#define VLINE (unicode?"│":"|") // vertical divider
#define HLINE (unicode?"─":"-") // horizontal divider
#define A_UP (unicode?"↑":"up") // arrow hints for the help line
#define A_DN (unicode?"↓":"dn")
#define A_LT (unicode?"←":"<-")
#define A_RT (unicode?"→":"->")
#define BOX_TL (unicode?"┌":"+") // box corners for the help dialog
#define BOX_TR (unicode?"┐":"+")
#define BOX_BL (unicode?"└":"+")
#define BOX_BR (unicode?"┘":"+")

// }}}

// {{{ signals

static void on_winch(int sig __attribute__((unused))) {
	f_winch=1;
}

static void on_stop(int sig __attribute__((unused))) {
	f_stop=1;
}

// an external kill -TSTP can land while yascreen is mid-write, and its calls
// are not async-signal-safe; only note the request here and let the event loop
// hand the terminal back at a safe point (do_suspend below). The Ctrl-Z key
// (ISIG is off, so it arrives as input) sets the same flag.
static void on_tstp(int sig __attribute__((unused))) {
	f_tstp=1;
}

static void on_cont(int sig __attribute__((unused))) {
	signal(SIGTSTP,on_tstp); // re-arm after the SIG_DFL stop in do_suspend
	f_cont=1;
}

// hand the terminal back and really stop; called from the event loop, in
// normal context, where the yascreen calls are safe
static void do_suspend(void) {
	yascreen_altbuf(scr,0);
	yascreen_cursor(scr,1);
	yascreen_term_restore(scr);
	signal(SIGTSTP,SIG_DFL);
	raise(SIGTSTP); // stops right here; on fg, on_cont re-arms the handler and schedules the screen reenter
}

// }}}

// {{{ packet ingest

static void tui_ingest(u_char *user,const struct pcap_pkthdr *h,const u_char *sp) { // {{{
	struct sess_model *m=(struct sess_model *)(void *)user; // via void *: pcap hands back the pointer we gave it, alignment intact
	struct dhcp_frame f;
	struct dhcp_msg msg;

	if (!dhcp_decap(sp,h->caplen,&f,NULL)) // NULL: no stderr diag, it would corrupt the screen
		return;
	if (g_keep&&!g_keep(f.payload,f.plen)) // -h CHADDR filter
		return;
	if (!dhcp_parse(f.payload,f.plen,&msg))
		return;
	msg.ts=h->ts; // use the capture time, not wall clock
	msg.raw=f.payload; // kept as a copy by the model for the full packet view
	msg.rawlen=f.plen;
	msg.srcip=ntohl(f.srcip);
	memcpy(msg.vlan,f.vlan,sizeof msg.vlan);
	msg.nvlan=f.nvlan;
	sess_ingest(m,&msg);
} // }}}

// }}}

// {{{ formatting helpers

static const char *state_name(enum tx_state st) { // {{{
	switch (st) {
		case TX_WAIT:
			return "wait";
		case TX_OFFERED:
			return "offered";
		case TX_COMPLETE:
			return "complete";
		case TX_NAK:
			return "NAK";
		case TX_DECLINED:
			return "declined";
		case TX_TIMEOUT:
			return "timeout";
	}
	return "?";
} // }}}

static uint32_t state_attr(enum tx_state st) { // {{{ colour per transaction state
	switch (st) {
		case TX_TIMEOUT:
			return YAS_FGCOLOR(YAS_RED)|YAS_BOLD;
		case TX_NAK:
			return YAS_FGCOLOR(YAS_RED);
		case TX_DECLINED: // a failure like NAK, but the client's call, hence its own colour
			return YAS_FGCOLOR(YAS_MAGENTA);
		case TX_WAIT:
			return YAS_FGCOLOR(YAS_YELLOW);
		case TX_OFFERED:
			return YAS_FGCOLOR(YAS_CYAN);
		case TX_COMPLETE:
			return YAS_FGCOLOR(YAS_GREEN);
	}
	return 0;
} // }}}

static void fmt_mac(char *b,size_t n,const uint8_t *mac,int len) { // {{{
	int i,p=0;

	if (len<=0||len>16)
		len=6;
	for (i=0;i<len&&p+3<(int)n;i++)
		p+=snprintf(b+p,n-p,"%s%02x",i?":":"",mac[i]);
} // }}}

static void fmt_ip(char *b,size_t n,uint32_t ip) { // {{{
	if (!ip)
		snprintf(b,n,"-");
	else
		snprintf(b,n,"%u.%u.%u.%u",(ip>>24)&255,(ip>>16)&255,(ip>>8)&255,ip&255);
} // }}}

static void fmt_vlan(char *b,size_t n,const struct dhcp_vlan *v,int nv) { // {{{ stacked tags as outer.inner vlan ids
	int i,p=0;

	if (n)
		b[0]=0;
	for (i=0;i<nv&&p<(int)n;i++)
		p+=snprintf(b+p,n-p,"%s%u",i?".":"",v[i].id);
} // }}}

static void fmt_age(char *b,size_t n,long s) { // {{{
	if (s<0)
		s=0;
	if (s<60)
		snprintf(b,n,"%lds",s);
	else if (s<3600)
		snprintf(b,n,"%ldm",s/60);
	else if (s<86400)
		snprintf(b,n,"%ldh",s/3600);
	else
		snprintf(b,n,"%ldd",s/86400);
} // }}}

// }}}

// {{{ selection

static int mac_match(const struct sess *s) { // {{{ same rule as same_client() in the model, hlen included
	int n=sel_hlen>16?16:sel_hlen;

	if (s->hlen!=sel_hlen)
		return 0;
	if (n==0)
		n=16;
	return s->htype==sel_htype&&!memcmp(s->chaddr,sel_mac,n);
} // }}}

static void on_msg_evict(const struct sess_msg *mm,void *user __attribute__((unused))) { // {{{ the model is about to free this message; drop every pointer kept to it so none outlives the node
	int i,j=0;

	if (sel_msg==mm)
		sel_msg=NULL;
	for (i=0;i<ov_n;i++) // compact it out of the flattened packet list
		if (ov_list[i]!=mm)
			ov_list[j++]=ov_list[i];
	ov_n=j;
	for (i=0;i<ndrows;i++) // and scrub the detail rows, detail_move reads them between frames
		if (drows[i].msg==mm)
			drows[i].msg=NULL;
} // }}}

static void set_sel(const struct sess *s) { // {{{
	if (!s) {
		sel_valid=0;
		return;
	}
	memcpy(sel_mac,s->chaddr,16);
	sel_hlen=s->hlen;
	sel_htype=s->htype;
	sel_valid=1;
} // }}}

static struct sess *sess_at(struct sess_model *m,int idx) { // {{{ nth client, clamped to [head,tail]
	struct sess *s=m->head;
	int i=0;

	if (idx<0)
		idx=0;
	while (s&&s->next&&i<idx) { // stop at the last client instead of running off the end
		s=s->next;
		i++;
	}
	return s;
} // }}}

static struct sess *cur_sel(struct sess_model *m,int *idx) { // {{{ selected client and its index; anchors to head if the old one is gone
	struct sess *s;
	int i=0;

	if (sel_valid)
		for (s=m->head;s;s=s->next,i++)
			if (mac_match(s)) {
				if (idx)
					*idx=i;
				return s;
			}
	if (m->head) {
		set_sel(m->head);
		if (idx)
			*idx=0;
		return m->head;
	}
	sel_valid=0;
	if (idx)
		*idx=0;
	return NULL;
} // }}}

// }}}

// {{{ low level drawing

static void draw_bar(int y,int sx,const char *left,const char *right) { // {{{ full width inverse bar with left/right text
	int rl=(int)strlen(right);

	// fill with spaces first (1 byte == 1 column) so multibyte glyphs in the
	// text cannot leave the inverse bar short of the right edge, then overlay
	yascreen_printxy(scr,0,y,YAS_INVERSE,"%*s",sx,"");
	yascreen_putsxy(scr,0,y,YAS_INVERSE,left);
	if (rl<sx)
		yascreen_putsxy(scr,sx-rl,y,YAS_INVERSE,right);
} // }}}

static int dwidth(const char *s) { // {{{ display cell width of a UTF-8 string (locale aware, see iotop u8strpadt)
	size_t si=0,sl=strlen(s);
	int w=0;

	mbtowc(NULL,NULL,0); // reset the shift state
	while (s[si]) {
		wchar_t wc;
		int cl=mbtowc(&wc,s+si,sl-si);
		int cw;

		if (cl<=0) {
			si++;
			continue;
		}
		cw=wcwidth(wc);
		if (cw>0)
			w+=cw;
		si+=cl;
	}
	return w;
} // }}}

static const char *u8skip(const char *s,int cells) { // {{{ pointer past the first `cells` display columns of s
	size_t si=0,sl=strlen(s);
	int tl=0;

	mbtowc(NULL,NULL,0);
	while (s[si]&&tl<cells) {
		wchar_t wc;
		int cl=mbtowc(&wc,s+si,sl-si);
		int cw;

		if (cl<=0) {
			si++;
			continue;
		}
		cw=wcwidth(wc);
		si+=cl;
		if (cw>0)
			tl+=cw;
	}
	return s+si;
} // }}}

static void draw_clip(int x,int y,int w,uint32_t attr,const char *str) { // {{{ draw exactly w display cells (truncate then space pad)
	char buf[1024];
	size_t si=0,sl,di=0;
	int tl=0;

	if (w<=0)
		return;
	if (!str)
		str="";
	sl=strlen(str);
	mbtowc(NULL,NULL,0);
	while (str[si]&&di<sizeof buf-1) {
		wchar_t wc;
		int cl=mbtowc(&wc,str+si,sl-si);
		int cw;

		if (cl<=0) {
			si++;
			continue;
		}
		cw=wcwidth(wc);
		if (cw<0) { // unprintable: drop it
			si+=cl;
			continue;
		}
		if (cw&&tl+cw>w) // next glyph would overflow the field
			break;
		if (di+(size_t)cl>=sizeof buf-1)
			break;
		memcpy(buf+di,str+si,cl);
		di+=cl;
		si+=cl;
		tl+=cw;
	}
	buf[di]=0;
	yascreen_putsxy(scr,x,y,attr,buf);
	if (tl<w) // pad the remainder with spaces (1 byte == 1 cell)
		yascreen_printxy(scr,x+tl,y,attr,"%*s",w-tl,"");
} // }}}

static void draw_vline(int x,int y,int h) { // {{{
	int i;

	for (i=0;i<h;i++)
		yascreen_putsxy(scr,x,y+i,0,VLINE);
} // }}}

static void draw_hline(int x,int y,int w) { // {{{
	int i;

	for (i=0;i<w;i++)
		yascreen_putsxy(scr,x+i,y,0,HLINE);
} // }}}

// iotop / flashosupgrade style scrollbars: end arrows and a proportional thumb,
// with 1/8 cell precision in UTF-8 mode and plain markers in ASCII mode
static const char *scr_u[12]={" ","▲","▼","⬍","▁","▂","▃","▄","▅","▆","▇","█"};
static const char *scr_a[4]={" ","^","v",":"};
static const char *hsc_u[12]={" ","◀","▶","⬌","▏","▎","▍","▌","▋","▊","▉","█"};
static const char *hsc_a[4]={" ","<",">",":"};

static void draw_vscroll(int x,int from,int to,int items,int pos) { // {{{ vertical scrollbar in column x over rows [from,to] (geometry mirrors flashosupgrade)
	int un=unicode;
	int visible=to-from+1;
	int begpos=from,endpos=to,i;

	if (items<1)
		items=1;
	if (from>to)
		return;
	if (from==to) { // a single cell can only mean both directions
		yascreen_putsxy(scr,x,from,YAS_INVERSE,un?scr_u[3]:scr_a[3]);
		return;
	}
	if (items>visible) { // thumb position and size, in 1/8 cell units when unicode
		int linecnt=visible-2; // rows usable by the thumb (between the arrows)
		int drscale=un?8:1;
		int y=drscale*linecnt; // total thumb travel space
		int ss=y*visible/items; // thumb size
		int min_ss=un?8:1;
		int adjss=ss<min_ss?min_ss:ss;
		int vss=y-adjss+1; // travel space without the thumb size

		begpos=(from+1)*drscale+vss*pos/(items-visible);
		endpos=begpos+adjss-1*(!un);
	}
	for (i=from;i<=to;i++) {
		if (i==from||i==to) { // end arrows
			yascreen_putsxy(scr,x,i,YAS_INVERSE,un?scr_u[i==from?1:2]:scr_a[i==from?1:2]);
			continue;
		}
		if (items<=visible) { // everything fits: a full thumb
			yascreen_putsxy(scr,x,i,un?0:YAS_INVERSE,un?scr_u[11]:scr_a[0]);
			continue;
		}
		if (un) {
			if (i<begpos/8||endpos/8<i)
				yascreen_putsxy(scr,x,i,0,scr_u[0]);
			else if (i==begpos/8)
				yascreen_putsxy(scr,x,i,0,scr_u[4+7-begpos%8]);
			else if (i==endpos/8)
				yascreen_putsxy(scr,x,i,YAS_INVERSE,scr_u[4+7-endpos%8]);
			else
				yascreen_putsxy(scr,x,i,0,scr_u[11]);
		} else {
			if (i<begpos||endpos<i)
				yascreen_putsxy(scr,x,i,0,scr_a[0]);
			else
				yascreen_putsxy(scr,x,i,YAS_INVERSE,scr_a[0]);
		}
	}
} // }}}

static void draw_hscroll(int y,int from,int to,int items,int pos) { // {{{ horizontal scrollbar in row y over columns [from,to] (cell precision)
	int un=unicode;
	int visible=to-from+1;
	int tb,te,i;

	if (items<1)
		items=1;
	if (from>to)
		return;
	if (from==to) {
		yascreen_putsxy(scr,from,y,YAS_INVERSE,un?hsc_u[3]:hsc_a[3]);
		return;
	}
	if (items<=visible) { // full thumb between the arrows
		tb=from+1;
		te=to-1;
	} else {
		int track=visible-2;
		int ts=track*visible/items;
		int space;

		if (ts<1)
			ts=1;
		space=track-ts;
		tb=from+1+(space>0?space*pos/(items-visible):0);
		te=tb+ts-1;
	}
	for (i=from;i<=to;i++) {
		if (i==from)
			yascreen_putsxy(scr,i,y,YAS_INVERSE,un?hsc_u[1]:hsc_a[1]);
		else if (i==to)
			yascreen_putsxy(scr,i,y,YAS_INVERSE,un?hsc_u[2]:hsc_a[2]);
		else if (i>=tb&&i<=te)
			yascreen_putsxy(scr,i,y,un?0:YAS_INVERSE,un?hsc_u[11]:hsc_a[0]);
		else
			yascreen_putsxy(scr,i,y,0,un?hsc_u[0]:hsc_a[0]);
	}
} // }}}

// }}}

// {{{ panes

static void draw_list(struct sess_model *m,int x,int y,int w,int h,int selidx,int *top,const struct timeval *now,int active) { // {{{
	char hdr[512];
	struct sess *s;
	int i,dataH,cw,sbx,vw=0;

	if (w<1||h<1)
		return;

	sbx=x+w-1; // rightmost column is the scrollbar
	cw=w-1; // width left for content; the 2 column gutter lives inside it

	for (s=m->head;s;s=s->next) // widest VLAN tag string; 0 means all untagged and the column is omitted
		if (s->nvlan) {
			char vb[16];

			fmt_vlan(vb,sizeof vb,s->vlan,s->nvlan);
			if ((int)strlen(vb)>vw)
				vw=(int)strlen(vb);
		}
	if (vw&&vw<4)
		vw=4; // no narrower than the VLAN header

	if (vw)
		snprintf(hdr,sizeof hdr,"%-17s %-8s %-15s %*s %3s %5s  %s","MAC","STATE","LEASE",vw,"VLAN","TX","AGE","HOST");
	else
		snprintf(hdr,sizeof hdr,"%-17s %-8s %-15s %3s %5s  %s","MAC","STATE","LEASE","TX","AGE","HOST");
	draw_clip(x+2,y,cw-2,YAS_BOLD,hdr); // leave a 2 column gutter for the selection marker

	dataH=h-1; // rows below the header
	if (dataH<1)
		return;

	if (selidx<*top) // keep the selection visible
		*top=selidx;
	if (selidx>=*top+dataH)
		*top=selidx-dataH+1;
	if (*top<0)
		*top=0;

	draw_vscroll(sbx,y+1,y+h-1,m->nsess,*top);

	if (m->nsess==0) {
		draw_clip(x+2,y+1,cw-2,0,"waiting for DHCP traffic ...");
		return;
	}

	s=m->head;
	for (i=0;i<*top&&s;i++)
		s=s->next;
	for (i=0;i<dataH&&s;i++,s=s->next) {
		char mac[MACSTR],lease[20],age[24],vb[16],line[512];
		enum tx_state st=s->txs?sess_tx_state(s->txs,now):TX_COMPLETE;
		int sel=*top+i==selidx;
		uint32_t attr=sel&&active?YAS_INVERSE:state_attr(st);

		fmt_mac(mac,sizeof mac,s->chaddr,s->hlen);
		fmt_ip(lease,sizeof lease,s->lease_ip);
		fmt_age(age,sizeof age,(long)(now->tv_sec-s->last.tv_sec));
		if (vw) {
			fmt_vlan(vb,sizeof vb,s->vlan,s->nvlan); // empty for an untagged client
			snprintf(line,sizeof line,"%-17s %-8s %-15s %*s %3d %5s  %s",
				mac,state_name(st),lease,vw,vb,s->ntx,age,s->hostname);
		} else
			snprintf(line,sizeof line,"%-17s %-8s %-15s %3d %5s  %s",
				mac,state_name(st),lease,s->ntx,age,s->hostname);
		draw_clip(x+2,y+1+i,cw-2,attr,line);
		if (sel) { // active pane: inverse row; inactive pane: a marker in the gutter
			if (active)
				draw_clip(x,y+1+i,2,YAS_INVERSE,"  ");
			else
				yascreen_putsxy(scr,x,y+1+i,0,MARK);
		}
	}
} // }}}

static void drow_add(uint32_t attr,struct sess_msg *msg,const char *text) { // {{{ append one detail row
	if (ndrows<(int)(sizeof drows/sizeof *drows)) {
		drows[ndrows].attr=attr;
		drows[ndrows].msg=msg;
		snprintf(drows[ndrows].text,sizeof drows[ndrows].text,"%s",text);
		ndrows++;
	}
} // }}}

static void build_detail_rows(struct sess *s,const struct timeval *now) { // {{{ flatten a client into detail rows (header, summary, per-message rows)
	char buf[256],pre[64],mac[MACSTR],ip1[20],ip2[20],age[24];
	struct sess_tx *tx;
	int vw=0,fw;

	ndrows=0;
	if (!s)
		return;

	for (tx=s->txs;tx;tx=tx->next) { // widest per-packet VLAN tag string; 0 means all untagged
		struct sess_msg *mm;

		for (mm=tx->msgs;mm;mm=mm->next)
			if (mm->nvlan) {
				char vb[16];

				fmt_vlan(vb,sizeof vb,mm->vlan,mm->nvlan);
				if ((int)strlen(vb)>vw)
					vw=(int)strlen(vb);
			}
	}
	// Shared geometry: every timestamp in column 0, every IP in one column,
	// every age in one column after it, then the extras (srv/count). The
	// message rows hold a right aligned VLAN field between the timestamp
	// and the message type (blank when the packet is untagged); its width
	// also pushes the transaction rows' IP, which needs at least column 34
	// for its own timestamp, xid and state - met at a field width of 7.
	fw=vw+2>7?vw+2:7;

	fmt_mac(mac,sizeof mac,s->chaddr,s->hlen);
	snprintf(buf,sizeof buf,"Client %s%s%s",mac,s->hostname[0]?"  ":"",s->hostname);
	drow_add(YAS_BOLD,NULL,buf);
	fmt_ip(ip1,sizeof ip1,s->lease_ip);
	fmt_ip(ip2,sizeof ip2,s->server_ip);
	if (s->nvlan) {
		char vb[16];

		fmt_vlan(vb,sizeof vb,s->vlan,s->nvlan);
		snprintf(pre,sizeof pre,"htype %u  vlan %s",s->htype,vb);
	} else
		snprintf(pre,sizeof pre,"htype %u",s->htype);
	// the lease sits in the pane's shared IP column, the client's last
	// activity in the age column and the server under the srv extras, like
	// the transaction rows below
	fmt_age(age,sizeof age,(long)(now->tv_sec-s->last.tv_sec));
	snprintf(buf,sizeof buf,"%-*s  %-15s  %4s  srv %s  %d tx",25+fw,pre,ip1,age,ip2,s->ntx);
	drow_add(0,NULL,buf);
	drow_add(0,NULL,""); // blank separator

	for (tx=s->txs;tx;tx=tx->next) {
		enum tx_state st=sess_tx_state(tx,now);
		struct sess_msg *mm;
		char tim[16];
		struct tm tmv;

		localtime_r(&tx->last.tv_sec,&tmv); // the transaction row carries its last event's time
		strftime(tim,sizeof tim,"%H:%M:%S",&tmv);
		fmt_age(age,sizeof age,(long)(now->tv_sec-tx->last.tv_sec));
		fmt_ip(ip1,sizeof ip1,tx->yiaddr);
		snprintf(buf,sizeof buf,"%s  xid %08x  %-8s%*s%-15s  %4s",tim,tx->xid,state_name(st),fw-5,"",tx->yiaddr?ip1:"",age);
		drow_add(state_attr(st),NULL,buf);
		for (mm=tx->msgs;mm;mm=mm->next) {
			uint32_t a=0,pip=0;
			char srv[40]="",cnt[16]="",vb[16]="";

			localtime_r(&mm->ts.tv_sec,&tmv);
			strftime(tim,sizeof tim,"%H:%M:%S",&tmv); // time of the last (retransmitted) copy
			fmt_age(age,sizeof age,(long)(now->tv_sec-mm->ts.tv_sec));
			if (mm->nvlan)
				fmt_vlan(vb,sizeof vb,mm->vlan,mm->nvlan);
			switch (mm->msgtype) { // the address that is the message's payload, not its transport
				case DHCPOFFER:
				case DHCPACK:
					pip=mm->yiaddr;
					break;
				case DHCPDISCOVER:
				case DHCPREQUEST:
				case DHCPDECLINE:
					pip=mm->reqip?mm->reqip:mm->ciaddr; // a renewing REQUEST names its lease in ciaddr
					break;
				case DHCPRELEASE:
				case DHCPINFORM:
					pip=mm->ciaddr;
					break;
			}
			fmt_ip(ip1,sizeof ip1,pip);
			if (mm->serverid) {
				fmt_ip(ip2,sizeof ip2,mm->serverid);
				snprintf(srv,sizeof srv,"  srv %s",ip2);
			}
			if (mm->count>1)
				snprintf(cnt,sizeof cnt,"  x%d",mm->count);
			// an offer from a server the client did not pick shows in yellow
			if (mm->msgtype==DHCPOFFER&&tx->selected_server&&mm->serverid&&mm->serverid!=tx->selected_server)
				a=YAS_FGCOLOR(YAS_YELLOW);
			snprintf(buf,sizeof buf,"%s  %*s  %-14s %-15s  %4s%s%s",tim,fw,vb,dhcp_msgtype_name(mm->msgtype),pip?ip1:"",age,srv,cnt);
			drow_add(a,mm,buf);
		}
	}
} // }}}

static void draw_detail(struct sess *s,int x,int y,int w,int h,const struct timeval *now,int active) { // {{{ per-message rows; a cursor tracks sel_msg when the pane is active
	int i,cursor=-1,cw,sbx;

	if (w<1||h<1)
		return;

	sbx=x+w-1; // rightmost column is the scrollbar
	cw=w-1; // content width

	if (!s) {
		draw_clip(x,y,cw,0,"(no client selected)");
		draw_vscroll(sbx,y,y+h-1,0,0);
		return;
	}

	build_detail_rows(s,now);
	detail_h=h; // remembered for the keypress-driven line scroll in detail_move

	if (active) // locate the cursor row
		for (i=0;i<ndrows;i++)
			if (drows[i].msg&&drows[i].msg==sel_msg) {
				cursor=i;
				break;
			}
	if (cursor>=0) { // keep the cursor visible
		if (cursor<detail_top)
			detail_top=cursor;
		if (cursor>=detail_top+h)
			detail_top=cursor-h+1;
	}
	if (detail_top>ndrows-h)
		detail_top=ndrows-h;
	if (detail_top<0)
		detail_top=0;

	draw_vscroll(sbx,y,y+h-1,ndrows,detail_top);

	for (i=0;i<h&&detail_top+i<ndrows;i++) {
		struct drow *d=&drows[detail_top+i];
		uint32_t attr=active&&d->msg&&d->msg==sel_msg?YAS_INVERSE:d->attr;

		draw_clip(x,y+i,cw,attr,d->text);
	}
} // }}}

// }}}

// {{{ render

static void render(struct sess_model *m,int live,int *top) { // {{{
	int sx=yascreen_sx(scr),sy=yascreen_sy(scr);
	char left[128],right[128];
	struct timeval now;
	struct sess *sel;
	int selidx=0,cy,ch;

	yascreen_clear_mem(scr,0);
	if (sx<1||sy<1)
		return;
	if (live)
		gettimeofday(&now,NULL);
	else
		now=m->now;

	snprintf(left,sizeof left," dhcpdump %s  %s",VERSION,live?"LIVE":"FILE");
	snprintf(right,sizeof right,"%d client%s ",m->nsess,m->nsess==1?"":"s");
	draw_bar(0,sx,left,right);

	sel=cur_sel(m,&selidx);
	ov_build(sel); // flat message list, used by the detail cursor and the overlay

	detail_h=0; // set again in draw_detail when the pane is actually drawn
	cy=1; // content rows 1 .. sy-2
	ch=sy-2;
	if (ch>=1) {
		int lf=focus==FOCUS_LIST,df=focus==FOCUS_DETAIL;

		if (layout==LAYOUT_VSPLIT&&sx>=40) {
			int lw=sx*2/5,rw;

			if (lw<24)
				lw=24;
			if (lw>60)
				lw=60;
			if (lw>sx-20)
				lw=sx-20;
			rw=sx-lw-1;
			draw_list(m,0,cy,lw,ch,selidx,top,&now,lf);
			draw_vline(lw,cy,ch);
			draw_detail(sel,lw+1,cy,rw,ch,&now,df);
		} else if (ch>=6) { // top/bottom split
			int lh=ch/2,dh;

			dh=ch-lh-1;
			draw_list(m,0,cy,sx,lh,selidx,top,&now,lf);
			draw_hline(0,cy+lh,sx);
			draw_detail(sel,0,cy+lh+1,sx,dh,&now,df);
		} else // too short to split, list only
			draw_list(m,0,cy,sx,ch,selidx,top,&now,lf);
	}

	if (focus==FOCUS_DETAIL)
		snprintf(left,sizeof left," q quit  %s/%s packet  %s open  %s back  v layout  ? help",A_UP,A_DN,A_RT,A_LT);
	else
		snprintf(left,sizeof left," q quit  %s/%s clients  %s packets  v layout  ? help",A_UP,A_DN,A_RT);
	snprintf(right,sizeof right,"%d/%d ",m->nsess?selidx+1:0,m->nsess);
	draw_bar(sy-1,sx,left,right);
} // }}}

// }}}

// {{{ packet detail overlay

static void ov_build(struct sess *s) { // {{{ flatten the client's packets, newest transaction first
	struct sess_tx *tx;

	ov_n=0;
	if (!s) // no client selected (e.g. empty model at the start of a live capture)
		return;
	for (tx=s->txs;tx;tx=tx->next) {
		struct sess_msg *mm;

		for (mm=tx->msgs;mm;mm=mm->next)
			if (ov_n<(int)(sizeof ov_list/sizeof *ov_list))
				ov_list[ov_n++]=mm;
	}
} // }}}

static void msg_move(int dir) { // {{{ move the detail/packet cursor by dir within ov_list (clamped)
	int i,idx=-1;

	for (i=0;i<ov_n;i++)
		if (ov_list[i]==sel_msg) {
			idx=i;
			break;
		}
	if (idx<0)
		idx=0;
	else {
		idx+=dir;
		if (idx<0)
			idx=0;
		if (idx>=ov_n)
			idx=ov_n-1;
	}
	sel_msg=ov_n>0?ov_list[idx]:NULL;
} // }}}

static void detail_move(int dir) { // {{{ move the detail cursor by one; scroll a single line per keypress over non-selectable rows
	int i,c=-1;

	if (detail_h<1) { // detail pane not on screen: plain cursor move
		msg_move(dir);
		return;
	}
	for (i=0;i<ndrows;i++)
		if (drows[i].msg&&drows[i].msg==sel_msg) {
			c=i;
			break;
		}
	if (c<0) {
		msg_move(dir);
		return;
	}
	if (dir<0) {
		int p=-1;

		for (i=c-1;i>=0;i--)
			if (drows[i].msg) {
				p=i;
				break;
			}
		if (p>=0&&p>=detail_top) { // previous selectable row already visible: just move to it
			sel_msg=drows[p].msg;
			return;
		}
		if (detail_top>0) { // hidden above: scroll a single line, select it only once it shows
			detail_top--;
			if (p==detail_top)
				sel_msg=drows[p].msg;
		}
	} else {
		int nx=-1;

		for (i=c+1;i<ndrows;i++)
			if (drows[i].msg) {
				nx=i;
				break;
			}
		if (nx>=0&&nx<detail_top+detail_h) { // next selectable row already visible: just move to it
			sel_msg=drows[nx].msg;
			return;
		}
		if (detail_top<ndrows-detail_h) { // hidden below: scroll a single line, select it only once it shows
			detail_top++;
			if (nx>=0&&nx<detail_top+detail_h)
				sel_msg=drows[nx].msg;
		}
	}
} // }}}

static int draw_text(int x,int y,int w,int h,const char *text,int top,int hoff) { // {{{ draw lines [top,top+h), skipping hoff columns; return line count
	const char *p=text;
	int li=0;

	while (*p) {
		const char *nl=strchr(p,'\n');
		int len=nl?(int)(nl-p):(int)strlen(p);

		if (li>=top&&li<top+h) {
			char line[1024],*ov;
			int c=len<(int)sizeof line-1?len:(int)sizeof line-1;

			memcpy(line,p,c);
			line[c]=0;
			draw_clip(x,y+li-top,w,0,hoff>0?u8skip(line,hoff):line);
			// recolor the decoder's overload marker, identified by its \1 tag
			// (never rendered from packet data, so a crafted literal
			// "<overloaded>" field value stays in the default colour); plain
			// yellow reads as brown on classic palettes
			ov=strstr(line,"\1<overloaded>");
			if (ov) {
				int col;

				*ov=0; // measure the prefix width in place; the tag itself is zero width
				col=dwidth(line)-hoff;
				if (col>=0&&col<w)
					draw_clip(x+col,y+li-top,w-col<12?w-col:12,YAS_FGCOLOR(YAS_YELLOW),"<overloaded>");
			}
		}
		li++;
		if (!nl)
			break;
		p=nl+1;
	}
	return li;
} // }}}

static void render_overlay(struct sess *s,int sx,int sy) { // {{{ full-screen decode of one packet
	char title[256],mac[MACSTR],sip[24],ts[40],right[64];
	struct sess_msg *mm;
	char *buf=NULL;
	size_t sz=0;
	struct tm tmv;
	int total=0,bodyH,maxw=0,cx,cw,hoff,availW,hbar,sbx;

	yascreen_clear_mem(scr,0);
	if (sx<1||sy<1)
		return;
	if (!s) { // selected client gone
		ov_active=0;
		return;
	}
	ov_build(s);
	if (ov_n<=0) { // client lost its packets (e.g. evicted); leave the view
		ov_active=0;
		return;
	}
	ov_pkt=-1; // follow the exact packet (sel_msg) across arrivals that shift indices
	if (sel_msg) {
		int k;

		for (k=0;k<ov_n;k++)
			if (ov_list[k]==sel_msg) {
				ov_pkt=k;
				break;
			}
	}
	if (ov_pkt<0) // sel_msg gone (evicted): fall back to the newest packet
		ov_pkt=0;
	sel_msg=ov_list[ov_pkt]; // keep the detail cursor in sync
	mm=ov_list[ov_pkt];

	fmt_mac(mac,sizeof mac,s->chaddr,s->hlen);
	fmt_ip(sip,sizeof sip,mm->srcip);
	localtime_r(&mm->ts.tv_sec,&tmv);
	strftime(ts,sizeof ts,"%H:%M:%S",&tmv);
	snprintf(title,sizeof title," packet %d/%d  %s  from %s  %s.%03ld",
		ov_pkt+1,ov_n,dhcp_msgtype_name(mm->msgtype),sip,ts,mm->ts.tv_usec/1000);
	draw_bar(0,sx,title,mac);

	sbx=sx-1; // rightmost column reserved for the vertical scrollbar
	availW=sx>=2?sx-1:sx; // content width without the scrollbar column
	if (mm->raw&&sy>2) {
		FILE *f=open_memstream(&buf,&sz);

		if (f) {
			dhcp_fprint_payload(f,mm->raw,mm->rawlen,VLINE); // box glyph for the hex dump bars in UTF-8 mode
			fclose(f);
		}
	}
	if (buf) { // count lines and the widest line, in display cells (ignoring trailing blanks)
		size_t si=0,sl=strlen(buf);
		int col=0,lastnb=0;

		mbtowc(NULL,NULL,0);
		while (buf[si]) {
			wchar_t wc;
			int cl,gw;

			if (buf[si]=='\n') {
				total++;
				if (lastnb>maxw)
					maxw=lastnb;
				col=0;
				lastnb=0;
				si++;
				mbtowc(NULL,NULL,0);
				continue;
			}
			cl=mbtowc(&wc,buf+si,sl-si);
			if (cl<=0) {
				si++;
				continue;
			}
			gw=wcwidth(wc);
			if (gw>0)
				col+=gw;
			if (buf[si]!=' ') // remember the column after the last non blank glyph
				lastnb=col;
			si+=cl;
		}
		if (lastnb>maxw)
			maxw=lastnb;
	}
	hbar=maxw>availW; // a horizontal scrollbar is needed only when too wide to fit
	bodyH=sy-2-(hbar?1:0); // text rows 1 .. bodyH; row sy-2 holds the hscroll when present
	if (bodyH<0)
		bodyH=0;
	if (ov_scroll>total-bodyH) // clamp vertical scroll
		ov_scroll=total-bodyH;
	if (ov_scroll<0)
		ov_scroll=0;
	if (!hbar) { // fits: center the block, no horizontal scroll
		cx=(availW-maxw)/2;
		if (cx<0)
			cx=0;
		cw=maxw;
		hoff=0;
		ov_hscroll=0;
	} else { // too wide: left aligned and horizontally scrollable
		cx=0;
		cw=availW;
		if (ov_hscroll>maxw-availW)
			ov_hscroll=maxw-availW;
		if (ov_hscroll<0)
			ov_hscroll=0;
		hoff=ov_hscroll;
	}
	if (buf) {
		if (bodyH>0)
			draw_text(cx,1,cw,bodyH,buf,ov_scroll,hoff);
		free(buf);
	}
	if (sx>=2&&bodyH>0) // vertical scrollbar spans the text rows
		draw_vscroll(sbx,1,bodyH,total,ov_scroll);
	if (hbar&&bodyH>0) // horizontal scrollbar just below the text
		draw_hscroll(bodyH+1,0,availW-1,maxw,hoff);

	snprintf(right,sizeof right,"line %d/%d ",total?ov_scroll+1:0,total);
	if (hbar) // only meaningful when the decode is wider than the screen
		snprintf(title,sizeof title," Esc back   %s/%s packet   %s/%s scroll   </> pan   ? help",A_LT,A_RT,A_UP,A_DN);
	else
		snprintf(title,sizeof title," Esc back   %s/%s packet   %s/%s scroll   ? help",A_LT,A_RT,A_UP,A_DN);
	draw_bar(sy-1,sx,title,right);
} // }}}

// }}}

// {{{ help dialog

static void draw_box(int x,int y,int w,int h) { // {{{ opaque bordered box
	int i;

	if (w<2||h<2)
		return;
	yascreen_putsxy(scr,x,y,0,BOX_TL);
	yascreen_putsxy(scr,x+w-1,y,0,BOX_TR);
	yascreen_putsxy(scr,x,y+h-1,0,BOX_BL);
	yascreen_putsxy(scr,x+w-1,y+h-1,0,BOX_BR);
	for (i=1;i<w-1;i++) {
		yascreen_putsxy(scr,x+i,y,0,HLINE);
		yascreen_putsxy(scr,x+i,y+h-1,0,HLINE);
	}
	for (i=1;i<h-1;i++) {
		yascreen_putsxy(scr,x,y+i,0,VLINE);
		draw_clip(x+1,y+i,w-2,0,""); // blank the interior so the dialog is opaque
		yascreen_putsxy(scr,x+w-1,y+i,0,VLINE);
	}
} // }}}

static int draw_keys(int x,int y,const char *s) { // {{{ draw key tokens blue, separators/spaces in the default colour; return cells drawn
	const char *p=s;
	int col=0;

	while (*p) {
		const char *g=p;
		int sep=(*p==' '||*p=='/'||*p==','); // separators stay default; everything else is a key
		char tok[32];
		int tl,tw;

		while (*p&&(*p==' '||*p=='/'||*p==',')==sep) // one maximal run of the same class
			p++;
		tl=(int)(p-g);
		if (tl>(int)sizeof tok-1)
			tl=sizeof tok-1;
		memcpy(tok,g,tl);
		tok[tl]=0;
		tw=dwidth(tok);
		if (tw>0) {
			draw_clip(x+col,y,tw,sep?0:YAS_FGCOLOR(YAS_BLUE),tok);
			col+=tw;
		}
	}
	return col;
} // }}}

static void draw_help(int sx,int sy) { // {{{ centered dialog listing the keys for the current context
	char keys[24][48],desc[24][64];
	const char *title;
	int n=0,i,kw=0,dw=0,iw,bw,bh,bx,by;

	if (ov_active) {
		title=" packet view ";
		snprintf(keys[n],sizeof keys[0],"%s / %s",A_LT,A_RT);       snprintf(desc[n++],sizeof desc[0],"previous / next packet");
		snprintf(keys[n],sizeof keys[0],"%s / %s  j / k",A_UP,A_DN);snprintf(desc[n++],sizeof desc[0],"scroll");
		snprintf(keys[n],sizeof keys[0],"PgUp / PgDn");             snprintf(desc[n++],sizeof desc[0],"scroll a page");
		snprintf(keys[n],sizeof keys[0],"< / >");                   snprintf(desc[n++],sizeof desc[0],"pan when wider than the screen");
		snprintf(keys[n],sizeof keys[0],"Esc, Backspace");          snprintf(desc[n++],sizeof desc[0],"back to the detail pane");
	} else if (focus==FOCUS_DETAIL) {
		title=" detail pane ";
		snprintf(keys[n],sizeof keys[0],"%s / %s  j / k",A_UP,A_DN);snprintf(desc[n++],sizeof desc[0],"select packet");
		snprintf(keys[n],sizeof keys[0],"PgUp / PgDn");             snprintf(desc[n++],sizeof desc[0],"page");
		snprintf(keys[n],sizeof keys[0],"g / G");                   snprintf(desc[n++],sizeof desc[0],"first / last");
		snprintf(keys[n],sizeof keys[0],"%s, Enter",A_RT);          snprintf(desc[n++],sizeof desc[0],"open full decode");
		snprintf(keys[n],sizeof keys[0],"%s, Esc, Backspace",A_LT); snprintf(desc[n++],sizeof desc[0],"back to the client list");
		snprintf(keys[n],sizeof keys[0],"Tab, Shift-Tab");          snprintf(desc[n++],sizeof desc[0],"to the client list");
	} else {
		title=" client list ";
		snprintf(keys[n],sizeof keys[0],"%s / %s  j / k",A_UP,A_DN);snprintf(desc[n++],sizeof desc[0],"select client");
		snprintf(keys[n],sizeof keys[0],"PgUp / PgDn");             snprintf(desc[n++],sizeof desc[0],"page");
		snprintf(keys[n],sizeof keys[0],"g / G");                   snprintf(desc[n++],sizeof desc[0],"first / last");
		snprintf(keys[n],sizeof keys[0],"%s, Enter",A_RT);          snprintf(desc[n++],sizeof desc[0],"view its packets");
		snprintf(keys[n],sizeof keys[0],"Tab, Shift-Tab");          snprintf(desc[n++],sizeof desc[0],"to the detail pane");
	}
	keys[n][0]=0; desc[n++][0]=0; // blank separator
	snprintf(keys[n],sizeof keys[0],"v, V");                    snprintf(desc[n++],sizeof desc[0],"switch layout");
	snprintf(keys[n],sizeof keys[0],"u / a");                   snprintf(desc[n++],sizeof desc[0],"UTF-8 / ASCII glyphs");
	snprintf(keys[n],sizeof keys[0],"Ctrl-L");                  snprintf(desc[n++],sizeof desc[0],"redraw the screen");
	snprintf(keys[n],sizeof keys[0],"Ctrl-Z");                  snprintf(desc[n++],sizeof desc[0],"suspend");
	snprintf(keys[n],sizeof keys[0],"h, H, ?, F1");             snprintf(desc[n++],sizeof desc[0],"toggle this help");
	snprintf(keys[n],sizeof keys[0],"q, Ctrl-C");               snprintf(desc[n++],sizeof desc[0],"quit");

	for (i=0;i<n;i++) { // widest key column and widest description
		if (dwidth(keys[i])>kw)
			kw=dwidth(keys[i]);
		if (dwidth(desc[i])>dw)
			dw=dwidth(desc[i]);
	}
	iw=kw+2+dw; // keys, a 2 cell gap, then descriptions
	if (dwidth(title)>iw)
		iw=dwidth(title);
	bw=iw+4;
	bh=n+2;
	if (bw>sx)
		bw=sx;
	if (bh>sy)
		bh=sy;
	bx=(sx-bw)/2;
	by=(sy-bh)/2;
	if (bx<0)
		bx=0;
	if (by<0)
		by=0;

	draw_box(bx,by,bw,bh);
	yascreen_putsxy(scr,bx+2,by,YAS_BOLD,title); // title sits in the top border
	for (i=0;i<n&&i<bh-2;i++) {
		if (keys[i][0])
			draw_keys(bx+2,by+1+i,keys[i]);
		if (desc[i][0])
			draw_clip(bx+2+kw+2,by+1+i,dw,0,desc[i]);
	}
} // }}}

// }}}

// {{{ event loop

int tui_run(pcap_t *cap,struct sess_model *m,int live,int (*keep)(const uint8_t *,int)) { // {{{
	char errbuf[PCAP_ERRBUF_SIZE];
	int pcfd=-1;
	int top=0;
	int prc=0;

	g_keep=keep;
	sess_model_on_msg_free(m,on_msg_evict,NULL); // set before any ingest, the offline load below is one

	if (live) {
		if (pcap_setnonblock(cap,1,errbuf)==-1)
			fprintf(stderr,"pcap_setnonblock: %s\n",errbuf);
		pcfd=pcap_get_selectable_fd(cap);
	} else if (pcap_loop(cap,0,tui_ingest,(u_char *)m)==-1) // load the whole capture first; a truncated/corrupt file still loads up to the damage and is browsable
		fprintf(stderr,"pcap_loop: %s\n",pcap_geterr(cap)); // before the alternate screen: briefly visible now, and again after the TUI exits

	scr=yascreen_init(0,0);
	if (!scr) {
		fprintf(stderr,"cannot allocate screen\n");
		return -1;
	}
	setbuf(stdout,NULL);
	setlocale(LC_CTYPE,""); // honour the environment's locale
	unicode=!strcmp(nl_langinfo(CODESET),"UTF-8"); // default to box glyphs on a UTF-8 terminal
	yascreen_term_set(scr,YAS_NOBUFF|YAS_NOSIGN|YAS_NOECHO);
	yascreen_set_unicode(scr,unicode);
	yascreen_altbuf(scr,1);
	yascreen_cursor(scr,0);
	yascreen_esc_to(scr,50); // yield a lone ESC quickly, for closing the packet view

	signal(SIGWINCH,on_winch);
	signal(SIGINT,on_stop);
	signal(SIGTERM,on_stop);
	signal(SIGTSTP,on_tstp);
	signal(SIGCONT,on_cont);

	while (!f_stop) {
		fd_set r;
		struct timeval to;
		uint64_t essto;
		int fdmax,nn,ch;

		if (f_tstp) { // suspend requested: this is the safe point to let go of the terminal
			f_tstp=0;
			do_suspend();
		}
		if (f_cont) { // resumed after a suspend: reenter raw mode and the alternate screen
			yascreen_term_set(scr,YAS_NOBUFF|YAS_NOSIGN|YAS_NOECHO);
			yascreen_altbuf(scr,1);
			yascreen_cursor(scr,0);
			f_cont=0;
			f_winch=1; // the window may have been resized while stopped
		}
		if (f_winch) {
			yascreen_resize(scr,0,0);
			yascreen_redraw(scr);
			f_winch=0;
		}
		if (ov_active)
			render_overlay(cur_sel(m,NULL),yascreen_sx(scr),yascreen_sy(scr));
		else
			render(m,live,&top);
		if (help_active) // modal help dialog on top of the current view
			draw_help(yascreen_sx(scr),yascreen_sy(scr));
		yascreen_update(scr);

		FD_ZERO(&r);
		FD_SET(STDIN_FILENO,&r);
		fdmax=STDIN_FILENO;
		if (live&&pcfd>=0) {
			FD_SET(pcfd,&r);
			if (pcfd>fdmax)
				fdmax=pcfd;
		}
		to.tv_sec=0;
		essto=yascreen_willto(scr); // wake when a pending lone ESC times out, else refresh ~2x/sec
		to.tv_usec=(essto>0&&essto<500?(int)essto:500)*1000;

		nn=select(fdmax+1,&r,NULL,NULL,&to);
		if (nn<0) {
			if (errno==EINTR)
				continue;
			break;
		}

		if (FD_ISSET(STDIN_FILENO,&r)) {
			unsigned char buf[256];
			int got=read(STDIN_FILENO,buf,sizeof buf),i;

			if (got==0) // stdin closed
				f_stop=1;
			for (i=0;i<got;i++)
				yascreen_feed(scr,buf[i]);
		}

		yascreen_ckto(scr); // flush a pending single ESC after its timeout

		while ((ch=yascreen_getch_nowait(scr))!=YAS_K_NONE) {
			int page=yascreen_sy(scr)/2,i;
			struct sess *cs;

			if (page<1)
				page=1;

			if (ch=='q'||ch=='Q'||ch==YAS_K_C_C) { // quit from anywhere, including the packet view
				f_stop=1;
				continue;
			}
			if (ch=='h'||ch=='H'||ch=='?'||ch==YAS_K_F1) { // toggle the help dialog
				help_active=!help_active;
				continue;
			}
			// the help dialog is non-modal: it stays open and follows the
			// context, so every other key falls through to normal handling
			if (ch=='u'||ch=='a') { // toggle UTF-8 box glyphs / ASCII
				unicode=ch=='u';
				yascreen_set_unicode(scr,unicode);
				continue;
			}
			if (ch==YAS_K_C_Z) { // suspend from anywhere; ISIG is off, so the key arrives as input
				f_tstp=1; // acted on at the top of the loop, together with an external SIGTSTP
				continue;
			}

			if (ov_active) { // full-screen packet decode
				int by=yascreen_sy(scr)-3;

				if (by<1)
					by=1;
				if (ch==YAS_K_ESC||ch==YAS_K_BSP||ch==YAS_K_C_H) // back to the detail pane
					ov_active=0;
				else if (ch==YAS_K_LEFT) { // previous packet
					msg_move(-1);
					ov_scroll=0;
					ov_hscroll=0;
				} else if (ch==YAS_K_RIGHT) { // next packet
					msg_move(1);
					ov_scroll=0;
					ov_hscroll=0;
				} else if (ch==YAS_K_UP||ch=='k') {
					if (ov_scroll>0)
						ov_scroll--;
				} else if (ch==YAS_K_DOWN||ch=='j')
					ov_scroll++; // clamped in render
				else if (ch==YAS_K_PGUP) {
					ov_scroll-=by;
					if (ov_scroll<0)
						ov_scroll=0;
				} else if (ch==YAS_K_PGDN)
					ov_scroll+=by;
				else if (ch=='<') { // pan left when the decode is wider than the screen
					if (ov_hscroll>0)
						ov_hscroll--;
				} else if (ch=='>')
					ov_hscroll++; // clamped in render
				else if (ch==YAS_K_C_L)
					f_winch=1;
				continue;
			}

			if (ch=='v'||ch=='V') { // toggle layout (list/detail only; not in the packet view above)
				layout=layout==LAYOUT_VSPLIT?LAYOUT_HSPLIT:LAYOUT_VSPLIT;
				continue;
			}
			if (ch=='\t'||ch==YAS_K_TAB||ch==YAS_K_S_TAB) { // switch to the other pane (list/detail only; a no-op in the packet view above)
				if (focus==FOCUS_DETAIL)
					focus=FOCUS_LIST;
				else {
					cs=cur_sel(m,NULL);
					if (cs) {
						ov_build(cs);
						if (ov_n>0) {
							int found=0;

							for (i=0;i<ov_n;i++)
								if (ov_list[i]==sel_msg) {
									found=1;
									break;
								}
							focus=FOCUS_DETAIL;
							if (!found) { // a different client since last time: start at its first packet
								sel_msg=ov_list[0];
								detail_top=0;
							}
						}
					}
				}
				continue;
			}
			if (ch==YAS_K_C_L) { // ^L: force redraw
				f_winch=1;
				continue;
			}

			if (focus==FOCUS_DETAIL) { // pick a packet within the selected client
				if (ch==YAS_K_LEFT||ch==YAS_K_ESC||ch==YAS_K_BSP||ch==YAS_K_C_H) // back to the client list
					focus=FOCUS_LIST;
				else if (ch==YAS_K_RET||ch==YAS_K_RIGHT) { // open the full decode
					if (sel_msg) {
						ov_active=1;
						ov_scroll=0;
					}
				} else if (ch==YAS_K_UP||ch=='k')
					detail_move(-1);
				else if (ch==YAS_K_DOWN||ch=='j')
					detail_move(1);
				else if (ch==YAS_K_PGUP)
					for (i=0;i<page;i++)
						msg_move(-1);
				else if (ch==YAS_K_PGDN)
					for (i=0;i<page;i++)
						msg_move(1);
				else if ((ch=='g'||ch==YAS_K_HOME)&&ov_n>0) {
					sel_msg=ov_list[0];
					detail_top=0; // jump to the very top, headers included
				} else if ((ch=='G'||ch==YAS_K_END)&&ov_n>0)
					sel_msg=ov_list[ov_n-1];
				continue;
			}

			// FOCUS_LIST: pick a client
			if (ch==YAS_K_RIGHT||ch==YAS_K_RET) { // step into the detail pane
				cs=cur_sel(m,&i);
				if (cs) {
					ov_build(cs);
					if (ov_n>0) {
						focus=FOCUS_DETAIL;
						sel_msg=ov_list[0];
						detail_top=0;
					}
				}
			} else if (ch==YAS_K_UP||ch=='k') {
				cs=cur_sel(m,&i);
				if (cs&&cs->prev)
					set_sel(cs->prev);
				detail_top=0;
			} else if (ch==YAS_K_DOWN||ch=='j') {
				cs=cur_sel(m,&i);
				if (cs&&cs->next)
					set_sel(cs->next);
				detail_top=0;
			} else if (ch=='g'||ch==YAS_K_HOME) {
				set_sel(m->head);
				detail_top=0;
			} else if (ch=='G'||ch==YAS_K_END) {
				set_sel(m->tail);
				detail_top=0;
			} else if (ch==YAS_K_PGUP) {
				cur_sel(m,&i);
				set_sel(sess_at(m,i-page));
				detail_top=0;
			} else if (ch==YAS_K_PGDN) {
				cur_sel(m,&i);
				set_sel(sess_at(m,i+page));
				detail_top=0;
			}
		}

		// a dead capture (e.g. the interface went away) keeps its fd readable,
		// so looping on the error would spin at full CPU; stop instead
		if (live&&(pcfd<0||FD_ISSET(pcfd,&r))&&(prc=pcap_dispatch(cap,-1,tui_ingest,(u_char *)m))<0)
			break;
	}

	yascreen_altbuf(scr,0);
	yascreen_cursor(scr,1);
	yascreen_term_restore(scr);
	yascreen_free(scr);
	scr=NULL;

	if (prc<0) { // report only now, with the terminal sane again
		fprintf(stderr,"pcap_dispatch: %s\n",pcap_geterr(cap));
		return -1;
	}

	return 0;
} // }}}

// }}}
