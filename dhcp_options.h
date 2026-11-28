//
// this list was stolen from The DHCP Handbook by Droms and Lemon, Appendix D
//

#include <stdint.h> // opt_info below

// The first comment is the number, the last parameter is if it's verbosed
const char *dhcp_options[] = {
/*   0 */ "pad",
/*   1 */ "Subnet mask",
/*   2 */ "Time offset",
/*   3 */ "Router",
/*   4 */ "Time server",
/*   5 */ "Name server",
/*   6 */ "DNS server",
/*   7 */ "Log server",
/*   8 */ "Quotes server",
/*   9 */ "LPR server",
/*  10 */ "Impress server",
/*  11 */ "RLP server",
/*  12 */ "Hostname",
/*  13 */ "Boot file size",
/*  14 */ "Merit dump file",
/*  15 */ "Domain name",
/*  16 */ "Swap server",
/*  17 */ "Root path",
/*  18 */ "Extensions path",
/*  19 */ "IP forwarding",
/*  20 */ "Non-local source routing",
/*  21 */ "Policy filter",
/*  22 */ "Max dgram reasm size",
/*  23 */ "Default IP TTL",
/*  24 */ "Path MTU aging timeout",
/*  25 */ "Path MTU plateau table",
/*  26 */ "Interface MTU size",
/*  27 */ "All subnets local",
/*  28 */ "Broadcast address",
/*  29 */ "Perform mask discovery",
/*  30 */ "Mask supplier",
/*  31 */ "Perform router discovery",
/*  32 */ "Router solicitation",
/*  33 */ "Static route",
/*  34 */ "Trailer encapsulation",
/*  35 */ "ARP cache timeout",
/*  36 */ "Ethernet encapsulation",
/*  37 */ "TCP default TTL",
/*  38 */ "TCP keepalive interval",
/*  39 */ "TCP keepalive garbage",
/*  40 */ "NIS domain",
/*  41 */ "NIS servers",
/*  42 */ "NTP servers",
/*  43 */ "Vendor specific info",
/*  44 */ "NetBIOS name server",
/*  45 */ "NetBIOS dgram distrib srv",
/*  46 */ "NetBIOS node type",
/*  47 */ "NetBIOS scope",
/*  48 */ "X Window font server",
/*  49 */ "X Window display server",
/*  50 */ "Requested IP address",
/*  51 */ "IP address leasetime",
/*  52 */ "Option overload",
/*  53 */ "DHCP message type",
/*  54 */ "DHCP Server identifier",
/*  55 */ "Parameter Request List",
/*  56 */ "DHCP Error Message",
/*  57 */ "Maximum DHCP message size",
/*  58 */ "Renewal Time T1",
/*  59 */ "Rebinding Time T2",
/*  60 */ "Vendor class identifier",
/*  61 */ "Client-identifier",
/*  62 */ "Netware/IP domain name",
/*  63 */ "Netware/IP sub options",
/*  64 */ "NIS+ domain",
/*  65 */ "NIS+ servers",
/*  66 */ "TFTP server name",
/*  67 */ "Bootfile name",
/*  68 */ "Mobile IP home agent",
/*  69 */ "SMTP server",
/*  70 */ "POP3 server",
/*  71 */ "NNTP server",
/*  72 */ "WWW server",
/*  73 */ "Finger server",
/*  74 */ "IRC server",
/*  75 */ "StreetTalk server",
/*  76 */ "StreetTalk dir assist srv",
/*  77 */ "User-class Identification",
/*  78 */ "SLP-directory-agent",
/*  79 */ "SLP-service-scope",
/*  80 */ "Rapid Commit/Naming Auth",
/*  81 */ "Client FQDN",
/*  82 */ "Relay Agent Information",
/*  83 */ "Internet Storage NS (iSNS)",
/*  84 */ "REMOVED/Unassigned",
/*  85 */ "NDS server",
/*  86 */ "NDS tree name",
/*  87 */ "NDS context",
/*  88 */ "BCMCS Controller Domains",
/*  89 */ "BCMCS Controller IPv4 addr",
/*  90 */ "Authentication",
/*  91 */ "Last transaction time",
/*  92 */ "Associated-ip",
/*  93 */ "Client System",
/*  94 */ "Client NDI",
/*  95 */ "LDAP",
/*  96 */ "REMOVED/Unassigned",
/*  97 */ "UUID/GUID",
/*  98 */ "Open Group User Auth",
/*  99 */ "GEOCONF_CIVIC",
/* 100 */ "PCode - POSIX TZ String",
/* 101 */ "TCode - TZ Database name",
/* 102 */ "REMOVED/Unassigned",
/* 103 */ "REMOVED/Unassigned",
/* 104 */ "REMOVED/Unassigned",
/* 105 */ "REMOVED/Unassigned",
/* 106 */ "REMOVED/Unassigned",
/* 107 */ "REMOVED/Unassigned",
/* 108 */ "IPv6-Only Preferred",
/* 109 */ "DHCP 4o6 Source Address",
/* 110 */ "REMOVED/Unassigned",
/* 111 */ "???",
/* 112 */ "Netinfo Address",
/* 113 */ "Netinfo Tag",
/* 114 */ "DHCP Captive-Portal",
/* 115 */ "REMOVED/Unassigned",
/* 116 */ "DHCP Autoconfiguration",
/* 117 */ "Name Service Search",
/* 118 */ "Subnet selection",
/* 119 */ "Domain Search",
/* 120 */ "SIP Servers DHCP Option",
/* 121 */ "Classless Static Route",
/* 122 */ "CableLabs Client Config",
/* 123 */ "GeoConf Option",
/* 124 */ "V-I Vendor Class",
/* 125 */ "V-I Vendor-Specific Info",
/* 126 */ "REMOVED/Unassigned",
/* 127 */ "REMOVED/Unassigned",
/* 128 */ "PXE/Etherboot/DOCSIS",
/* 129 */ "PXE/Kernel opts/Call srv",
/* 130 */ "PXE/Ethernet interface",
/* 131 */ "PXE/Remote stats server",
/* 132 */ "PXE/802.1Q VLAN ID",
/* 133 */ "PXE/802.1p L2 Priority",
/* 134 */ "PXE/Diffserv CP for VoIP",
/* 135 */ "PXE/HTTP Proxy for phone",
/* 136 */ "OPTION_PANA_AGENT",
/* 137 */ "OPTION_V4_LOST",
/* 138 */ "OPTION_CAPWAP_AC_V4",
/* 139 */ "OPTION-IPv4_Address-MoS",
/* 140 */ "OPTION-IPv4_FQDN-MoS",
/* 141 */ "SIP UA Config SDomains",
/* 142 */ "OPTION-IPv4_Address-ANDSF",
/* 143 */ "OPTION_V4_SZTP_REDIRECT",
/* 144 */ "GeoLoc/HP - TFTP file",
/* 145 */ "FORCERENEW_NONCE_CAPABLE",
/* 146 */ "RDNSS Selection",
/* 147 */ "OPTION_V4_DOTS_RI",
/* 148 */ "OPTION_V4_DOTS_ADDRESS",
/* 149 */ "???",
/* 150 */ "TFTP addr/Etherboot/GRUB",
/* 151 */ "status-code",
/* 152 */ "base-time",
/* 153 */ "start-time-of-state",
/* 154 */ "query-start-time",
/* 155 */ "query-end-time",
/* 156 */ "dhcp-state",
/* 157 */ "data-source",
/* 158 */ "OPTION_V4_PCP_SERVER",
/* 159 */ "OPTION_V4_PORTPARAMS",
/* 160 */ "???",
/* 161 */ "OPTION_MUD_URL_V4",
/* 162 */ "OPTION_V4_DNR",
/* 163 */ "???",
/* 164 */ "???",
/* 165 */ "???",
/* 166 */ "???",
/* 167 */ "???",
/* 168 */ "???",
/* 169 */ "???",
/* 170 */ "???",
/* 171 */ "???",
/* 172 */ "???",
/* 173 */ "???",
/* 174 */ "???",
/* 175 */ "Etherboot Tent.2005-06-23",
/* 176 */ "IP Telephone (tentative)",
/* 177 */ "Etherboot Tent.2005-06-23",
/* 178 */ "???",
/* 179 */ "???",
/* 180 */ "???",
/* 181 */ "???",
/* 182 */ "???",
/* 183 */ "???",
/* 184 */ "???",
/* 185 */ "???",
/* 186 */ "???",
/* 187 */ "???",
/* 188 */ "???",
/* 189 */ "???",
/* 190 */ "???",
/* 191 */ "???",
/* 192 */ "???",
/* 193 */ "???",
/* 194 */ "???",
/* 195 */ "???",
/* 196 */ "???",
/* 197 */ "???",
/* 198 */ "???",
/* 199 */ "???",
/* 200 */ "???",
/* 201 */ "???",
/* 202 */ "???",
/* 203 */ "???",
/* 204 */ "???",
/* 205 */ "???",
/* 206 */ "???",
/* 207 */ "???",
/* 208 */ "PXELINUX Magic",
/* 209 */ "Configuration File",
/* 210 */ "Path Prefix",
/* 211 */ "Reboot Time",
/* 212 */ "OPTION_6RD",
/* 213 */ "OPTION_V4_ACCESS_DOMAIN",
/* 214 */ "???",
/* 215 */ "???",
/* 216 */ "???",
/* 217 */ "???",
/* 218 */ "???",
/* 219 */ "???",
/* 220 */ "Subnet Allocation",
/* 221 */ "Virtual Subnet Selection",
/* 222 */ "???",
/* 223 */ "???",
/* 224 */ "Reserved for private use",
/* 225 */ "Reserved for private use",
/* 226 */ "Reserved for private use",
/* 227 */ "Reserved for private use",
/* 228 */ "Reserved for private use",
/* 229 */ "Reserved for private use",
/* 230 */ "Reserved for private use",
/* 231 */ "Reserved for private use",
/* 232 */ "Reserved for private use",
/* 233 */ "Reserved for private use",
/* 234 */ "Reserved for private use",
/* 235 */ "Reserved for private use",
/* 236 */ "Reserved for private use",
/* 237 */ "Reserved for private use",
/* 238 */ "Reserved for private use",
/* 239 */ "Reserved for private use",
/* 240 */ "Reserved for private use",
/* 241 */ "Reserved for private use",
/* 242 */ "Reserved for private use",
/* 243 */ "Reserved for private use",
/* 244 */ "Reserved for private use",
/* 245 */ "Reserved for private use",
/* 246 */ "Reserved for private use",
/* 247 */ "Reserved for private use",
/* 248 */ "Reserved for private use",
/* 249 */ "MSFT - Classless route",
/* 250 */ "Reserved for private use",
/* 251 */ "Reserved for private use",
/* 252 */ "MSFT-WinSock Proxy AutoDet",
/* 253 */ "Reserved for private use",
/* 254 */ "Reserved for private use",
/* 255 */ "End",
};
// Indexed directly with the option code byte from the packet, unlike the
// tables below (bounds checked with strcountof), so it must name every code.
_Static_assert(sizeof dhcp_options/sizeof *dhcp_options==256,"dhcp_options must have exactly one entry per option code 0-255");

const char *dhcp_message_types[] = {
/*   0 */ "undefined",
/*   1 */ "DHCPDISCOVER",
/*   2 */ "DHCPOFFER",
/*   3 */ "DHCPREQUEST",
/*   4 */ "DHCPDECLINE",
/*   5 */ "DHCPACK",
/*   6 */ "DHCPNAK",
/*   7 */ "DHCPRELEASE",
/*   8 */ "DHCPINFORM",
/*   9 */ "DHCPFORCERENEW",
/*  10 */ "DHCPLEASEQUERY",
/*  11 */ "DHCPLEASEUNASSIGNED",
/*  12 */ "DHCPLEASEUNKNOWN",
/*  13 */ "DHCPLEASEACTIVE",
/*  14 */ "DHCPBULKLEASEQUERY",
/*  15 */ "DHCPLEASEQUERYDONE",
/*  16 */ "DHCPACTIVELEASEQUERY",
/*  17 */ "DHCPLEASEQUERYSTATUS",
/*  18 */ "DHCPTLS",
};

const char *netbios_node_type[] = {
/*   0 */ "none",
/*   1 */ "B-node",
/*   2 */ "P-node",
/*   3 */ "",
/*   4 */ "M-node",
/*   5 */ "",
/*   6 */ "",
/*   7 */ "",
/*   8 */ "H-node"
};

const char *option_overload[] = {
/*   0 */ "unspecified",
/*   1 */ "file field holds options",
/*   2 */ "sname field holds options",
/*   3 */ "file and sname field holds options"
};

const char *enabledisable[] = {
/*   0 */ "disabled",
/*   1 */ "enabled"
};

const char *ethernet_encapsulation[] = {
/*   0 */ "Ethernet version 2",
/*   1 */ "IEEE 802.3"
};

const char *operands[] = {
/*   0 */ "undefined",
/*   1 */ "BOOTPREQUEST",
/*   2 */ "BOOTPREPLY"
};

// From RFC 3046
const char *relayagent_suboptions[] = {
/*   0 */ "<unknown>",
/*   1 */ "Circuit-ID",
/*   2 */ "Remote-ID"
};

// Copied from RFC1700
const char *htypes[] = {
/*   0 */ "undefined",
/*   1 */ "Ethernet",
/*   2 */ "Experimental Ethernet",
/*   3 */ "Amateur Radio AX.25",
/*   4 */ "Proteon ProNET Token Ring",
/*   5 */ "Chaos",
/*   6 */ "IEEE 802 Networks",
/*   7 */ "ARCNET",
/*   8 */ "Hyperchannel",
/*   9 */ "Lanstar",
/*  10 */ "Autonet Short Address",
/*  11 */ "LocalTalk",
/*  12 */ "LocalNet",
/*  13 */ "Ultra link",
/*  14 */ "SMDS",
/*  15 */ "Frame Relay",
/*  16 */ "ATM",
/*  17 */ "HDLC",
/*  18 */ "Fibre Channel",
/*  19 */ "ATM",
/*  20 */ "Serial Line",
/*  21 */ "ATM",
/*  22 */ "MIL-STD-188-220",
/*  23 */ "Metricom",
/*  24 */ "IEEE 1394.1995",
/*  25 */ "MAPOS",
/*  26 */ "Twinaxial",
/*  27 */ "EUI-64",
/*  28 */ "HIPARP",
/*  29 */ "IP and ARP over ISO 7816-3",
/*  30 */ "ARPSec",
/*  31 */ "IPsec tunnel",
/*  32 */ "InfiniBand",
/*  33 */ "TIA-102 Project 25 Common Air Interface",
/*  34 */ "Wiegand Interface",
/*  35 */ "Pure IP",
/*  36 */ "HW_EXP1",
/*  37 */ "HFI",
/*  38 */ "Unified Bus"
};

// From RFC 4578 and errata
const char *client_architecture_names[] = {
/*   0 */ "Intel x86PC",
/*   1 */ "NEC/PC98",
/*   2 */ "Itanium",
/*   3 */ "DEC Alpha",
/*   4 */ "Arc x86",
/*   5 */ "Intel Lean Client",
/*   6 */ "EFI IA32",
/*   7 */ "EFI x86-64",
/*   8 */ "EFI Xscale",
/*   9 */ "EFI BC",
};

//From rfc 2563
const char *auto_configure[] = {
/*   0 */ "DoNotAutoConfigure",
/*   1 */ "AutoConfigure",
};

// Value type of each option code; it drives the option renderers in
// dhcpdump.c. A code that is not listed is OT_TEXT: shown as text when every
// byte is printable, as hex otherwise. Supporting a new option means adding
// its name above and, if it has a structure, one line here.
enum opt_type {
	OT_TEXT=0, // printable text, hex otherwise
	OT_ADDR, // one IPv4 address
	OT_ADDRS, // list of IPv4 addresses
	OT_ADDRMASKS, // list of address/mask pairs
	OT_ROUTES, // list of destination/router pairs
	OT_U8, // 8 bit number
	OT_U16, // 16 bit number
	OT_U16S, // list of 16 bit numbers
	OT_SECS, // 32 bit count of seconds
	OT_TIMEOFFSET, // 32 bit seconds, signed (RFC 2132 3.4)
	OT_ENUM, // 8 bit value with names
	OT_HEX, // raw bytes
	OT_PRL, // parameter request list: option codes
	OT_FQDN, // client FQDN: flags, two rcodes, name
	OT_RELAY, // relay agent information: sub-options
	OT_ARCH, // client system architectures: 16 bit types
	OT_NDI, // client network device interface: type, major, minor
	OT_CROUTES, // classless static routes (RFC 3442)
};

struct opt_info {
	uint8_t type; // enum opt_type
	const char **names; // OT_ENUM: names of the values
	unsigned nnames; // entries in names
};

#define OPT(t) {.type=(t)}
#define OPT_ENUM(n) {.type=OT_ENUM,.names=(n),.nnames=sizeof (n)/sizeof *(n)}

static const struct opt_info opt_info[256] = {
[  1] = OPT(OT_ADDR), // Subnet mask
[  2] = OPT(OT_TIMEOFFSET), // Time offset
[  3] = OPT(OT_ADDRS), // Router
[  4] = OPT(OT_ADDRS), // Time server
[  5] = OPT(OT_ADDRS), // Name server
[  6] = OPT(OT_ADDRS), // DNS server
[  7] = OPT(OT_ADDRS), // Log server
[  8] = OPT(OT_ADDRS), // Cookie server
[  9] = OPT(OT_ADDRS), // LPR server
[ 10] = OPT(OT_ADDRS), // Impress server
[ 11] = OPT(OT_ADDRS), // Resource location server
[ 13] = OPT(OT_U16), // Boot file size
[ 16] = OPT(OT_ADDR), // Swap server
[ 19] = OPT_ENUM(enabledisable), // IP forwarding
[ 20] = OPT_ENUM(enabledisable), // Non-local source routing
[ 21] = OPT(OT_ADDRMASKS), // Policy filter
[ 22] = OPT(OT_U16), // Maximum datagram reassembly size
[ 23] = OPT(OT_U8), // Default IP TTL
[ 24] = OPT(OT_SECS), // Path MTU aging timeout
[ 25] = OPT(OT_U16S), // Path MTU plateau table
[ 26] = OPT(OT_U16), // Interface MTU
[ 27] = OPT_ENUM(enabledisable), // All subnets are local
[ 28] = OPT(OT_ADDR), // Broadcast address
[ 29] = OPT_ENUM(enabledisable), // Perform mask discovery
[ 30] = OPT_ENUM(enabledisable), // Mask supplier
[ 31] = OPT_ENUM(enabledisable), // Perform router discovery
[ 32] = OPT(OT_ADDR), // Router solicitation address
[ 33] = OPT(OT_ROUTES), // Static route
[ 34] = OPT_ENUM(enabledisable), // Trailer encapsulation
[ 35] = OPT(OT_SECS), // ARP cache timeout
[ 36] = OPT_ENUM(ethernet_encapsulation), // Ethernet encapsulation
[ 37] = OPT(OT_U8), // TCP default TTL
[ 38] = OPT(OT_SECS), // TCP keepalive interval
[ 39] = OPT_ENUM(enabledisable), // TCP keepalive garbage
[ 41] = OPT(OT_ADDRS), // NIS servers
[ 42] = OPT(OT_ADDRS), // NTP servers
[ 44] = OPT(OT_ADDRS), // NetBIOS name server
[ 45] = OPT(OT_ADDRS), // NetBIOS datagram distribution server
[ 46] = OPT_ENUM(netbios_node_type), // NetBIOS node type
[ 48] = OPT(OT_ADDRS), // X Window font server
[ 49] = OPT(OT_ADDRS), // X Window display manager
[ 50] = OPT(OT_ADDR), // Requested IP address
[ 51] = OPT(OT_SECS), // IP address leasetime
[ 52] = OPT_ENUM(option_overload), // Option overload
[ 53] = OPT_ENUM(dhcp_message_types), // DHCP message type
[ 54] = OPT(OT_ADDR), // Server identifier
[ 55] = OPT(OT_PRL), // Parameter request list
[ 57] = OPT(OT_U16), // Maximum DHCP message size
[ 58] = OPT(OT_SECS), // T1
[ 59] = OPT(OT_SECS), // T2
[ 63] = OPT(OT_HEX), // NetWare/IP domain information
[ 65] = OPT(OT_ADDRS), // NIS+ servers
[ 68] = OPT(OT_ADDRS), // Mobile IP home agent
[ 69] = OPT(OT_ADDRS), // SMTP server
[ 70] = OPT(OT_ADDRS), // POP3 server
[ 71] = OPT(OT_ADDRS), // NNTP server
[ 72] = OPT(OT_ADDRS), // WWW server
[ 73] = OPT(OT_ADDRS), // Finger server
[ 74] = OPT(OT_ADDRS), // IRC server
[ 75] = OPT(OT_ADDRS), // StreetTalk server
[ 76] = OPT(OT_ADDRS), // StreetTalk directory assistance server
[ 78] = OPT(OT_ADDRS), // Directory agent
[ 81] = OPT(OT_FQDN), // Client FQDN
[ 82] = OPT(OT_RELAY), // Relay agent information
[ 85] = OPT(OT_ADDRS), // NDS server
[ 91] = OPT(OT_SECS), // Client last transaction time
[ 92] = OPT(OT_ADDRS), // Associated IP
[ 93] = OPT(OT_ARCH), // Client system architecture
[ 94] = OPT(OT_NDI), // Client network device interface
[108] = OPT(OT_SECS), // IPv6-only preferred
[116] = OPT_ENUM(auto_configure), // Auto-configure
[118] = OPT(OT_ADDR), // Subnet selection
[121] = OPT(OT_CROUTES), // Classless static route
[145] = OPT(OT_U8), // FORCERENEW_NONCE_CAPABLE
[148] = OPT(OT_ADDRS), // DOTS address
[150] = OPT(OT_ADDRS), // TFTP server address
[152] = OPT(OT_SECS), // base-time
[153] = OPT(OT_SECS), // start-time-of-state
[154] = OPT(OT_SECS), // query-start-time
[155] = OPT(OT_SECS), // query-end-time
[162] = OPT(OT_ADDRS), // Encrypted DNS server
[211] = OPT(OT_SECS), // reboot-time
[249] = OPT(OT_CROUTES), // MSFT classless route
};
