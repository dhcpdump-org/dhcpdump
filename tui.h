// {{{ header

#ifndef ___DHCPDUMP_TUI_H___
#define ___DHCPDUMP_TUI_H___

#include <pcap.h>

#include "session.h"

// }}}

// Interactive full-screen view of the session model, built on yascreen.
//
// For a live capture (live!=0) packets are ingested as they arrive through a
// select() based event loop over the pcap fd and the keyboard. For an offline
// file (live==0) the whole capture is loaded into the model first and then
// browsed. If keep is non-NULL it is called per packet with the DHCP payload
// and only packets for which it returns non-zero are tracked (the -h filter).
// Returns 0 on a normal quit.
int tui_run(pcap_t *cap,struct sess_model *m,int live,int (*keep)(const uint8_t *payload,int plen));

#endif
