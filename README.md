# Fork of dhcpdump
Parse DHCP packets from a network interface

This fork of `dhcpdump` 1.8 by Edwin Groothuis, edwin@mavetju.org (http://www.mavetju.org) collects in a single place bug-fixes and improvements collected over the last 10+ years.

## Version 2.01

* Add JSON output (`-j`): one object per DHCP packet per line; with `-H` it also carries the raw frame and every option's raw bytes as hex ([Don Steele](https://github.com/donaldsteele))
* Drive option decoding from a per-code type table ([Don Steele](https://github.com/donaldsteele))
* Clear capabilities when `-Z` drops privileges ([Don Steele](https://github.com/donaldsteele))
* Print option 2 (Time offset) as a signed value and option 23 (Default IP TTL) as a number ([Don Steele](https://github.com/donaldsteele))
* Decode option 78 (SLP directory agent, RFC 2610) and option 162 (encrypted DNS, RFC 9463)
* Print options 152, 154 and 155 (RFC 6926) as absolute times
* Decide what is printable as plain ASCII, whatever the locale
* Add regression tests (`make test`)

### JSON output

Run with `-j` to get one JSON object per DHCP packet per line (JSON Lines),
ready for `jq` or a log pipeline:

    dhcpdump -i eth0 -j | jq -c 'select(any(.options[]?; .code == 53 and .value == 6))'

Diagnostics stay on stderr. The schema is in the manual page.

## Version 2.00

* Add an interactive session-tracking TUI (`-t`)
* The TUI depends on [yascreen](https://github.com/bbonev/yascreen)
* Split packet parsing into a reusable decoder library separate from the CLI front end
* Fix VLAN (802.1Q) and QinQ (802.1ad) tagged DHCP
* The TUI is optional by `make NO_TUI=1`
* Add `-Z <user>` to drop privileges once the capture is open
* Distinguish plain BOOTP from DHCP and handle it better
* Better decoding of option 93
* Never print control characters from packet data, read all packet data as possibly unaligned and add more length checks
* Capture whole frames (larger snaplen)
* Send usage to stderr, exit non-zero on errors, fail early on a broken pcap file and exit when the interface disappears
* TUI: `v`/`V` switch the view mode, Tab/Shift-Tab move between the panes, Ctrl-Z (and an external SIGTSTP) suspends, scrolling fixes
* TUI: a RELEASE is not treated as a DECLINE, the packet store is bounded and robust against a non-monotonic clock
* More consistent formatting and alignment of the output
* Add `make scan` (clang static analyzer) and enable the extra warnings the compiler supports

### Session tracking

Run with `-t` for a full-screen, colour coded view that groups traffic into DHCP
sessions by client, and within each client into transactions by XID. Every
transaction shows its message flow (DISCOVER, OFFER, REQUEST, ACK, ...) and a
derived state: waiting for a reply, offered, complete/bound, NAK, or timed out.
It works both live (`-i`) and while browsing a capture (`-r`). See the manual
page for the full list of keys.

## Version 1.11 (unreleased, tagged)

* This tag keeps the last version that does not have TUI and does not depend on [yascreen](https://github.com/bbonev/yascreen)
* Harden the option parser against out-of-bounds reads and a stack overflow on crafted packets

## Changes since 1.8

* Fix the DHCP flags calculation
* Print option 82 content in a more usable way
* Avoid OOB access for the undefined string values
* Get ethertype in edian agnostic way
* Add/remove headers
* Use `char` for strings and `uint8_t` for binary data
* Let the `Makefile` use environment variables
* Spelling fixes
* Remove the unused `strsep` implementation
* Use a stricter filter for DHCP packets
* Add an option to dump packet content in HEX
* More consistent alignment of output
* Avoid extra new lines in parameter request list (option 55)
* Print client identifier as HEX+ASCII
* Print mac addresses with leading zeroes
* Add support for VLAN tagged traffic
* Add option to read traffic from pcap dump file
* Update option names and semantics from IANA ([Rob Gill](https://github.com/rrobgill))
* Parse classless static routes option 121 and 249 using compact address and mask format (RFC3422) ([Rob Gill](https://github.com/rrobgill))
* Parse PXE related options 93 and 94 (RFC4578 and errata) ([Rob Gill](https://github.com/rrobgill))
* Parse stateless autoconfigure option 116 (RFC2563) ([Rob Gill](https://github.com/rrobgill))
