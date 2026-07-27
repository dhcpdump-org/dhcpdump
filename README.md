# Fork of dhcpdump
Parse DHCP packets from a network interface

This fork of `dhcpdump` 1.8 by Edwin Groothuis, edwin@mavetju.org (http://www.mavetju.org) collects in a single place bug-fixes and improvements collected over the last 10+ years.

## Version 2.00pre1 (unreleased)

* Add an interactive session-tracking TUI (`-t`)
* The TUI depends on [yascreen](https://github.com/bbonev/yascreen)
* Split packet parsing into a reusable decoder library separate from the CLI front end
* Fix VLAN (802.1Q) and QinQ (802.1ad) tagged DHCP
* The TUI is optional by `make NO_TUI=1`

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
