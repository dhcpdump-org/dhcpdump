# dhcpdump - DHCP packet dumper and session tracker
#
# Build options (pass on the make command line):
#   NO_TUI=1   build without the interactive -t TUI. Drops the yascreen
#              dependency (and the session tracker); libpcap is then the only
#              external library. Default builds depend on both libpcap and
#              yascreen.
#
# Each external library is located the same way (see check_dep below): via
# pkg-config if it has a .pc file, else via a plain -l flag if that links, and
# if neither works the build stops with a clear message rather than a cryptic
# link error. libpcap is always required; yascreen only unless NO_TUI is set.

CFLAGS+=${CPPFLAGS}
CFLAGS+=-Wall -Wextra -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 -g -O3 -fPIE
LDFLAGS+=-g -Wl,-z,relro -Wl,-z,now -fPIE -pie

# check_dep: locate one dependency, uniformly.
#   $(call check_dep,<pkg-config module>,<link flag>,<human name>)
# Prefer pkg-config; else fall back to the link flag only if it actually links;
# else fail with an explanatory error.
define check_dep
ifeq ($$(shell pkg-config --exists $(1) 2>/dev/null && echo y),y)
CFLAGS+=$$(shell pkg-config --cflags $(1))
LIBS+=$$(shell pkg-config --libs $(1))
else ifeq ($$(shell printf 'int main(void){return 0;}\n' | $$(CC) -x c - $(2) -o /dev/null >/dev/null 2>&1 && echo y),y)
LIBS+=$(2)
else
$$(error $(3) not found: install its development package (pkg-config module '$(1)', or the $(2) library))
endif
endef

OBJS:=main.o dhcpdump.o
$(eval $(call check_dep,libpcap,-lpcap,libpcap))

ifdef NO_TUI
CFLAGS+=-DNO_TUI
else
$(eval $(call check_dep,yascreen,-lyascreen,yascreen))
OBJS+=dhcp.o session.o tui.o
endif

ifeq ($(shell uname -s),Darwin)
LDFLAGSTODROP:=-Wl,-z,relro -Wl,-z,now
LDFLAGS:=$(filter-out $(LDFLAGSTODROP),$(LDFLAGS))
endif

all: dhcpdump dhcpdump.8

clean:
	-rm -f main.o dhcpdump.o dhcp.o session.o tui.o dhcpdump dhcpdump.8

re:
	${MAKE} clean
	${MAKE} -j all

dhcpdump.8: dhcpdump.pod Makefile
	pod2man --section 8 \
		--date "23 June 2008" \
		--name "DHCPDUMP" \
		--center "User Contributed Software" \
		dhcpdump.pod dhcpdump.8

dhcpdump: ${OBJS} Makefile
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LIBS}

main.o: main.c dhcpdump.h tui.h session.h version.h Makefile
	${CC} ${CFLAGS} -c -o $@ main.c

dhcpdump.o: dhcpdump.c dhcpdump.h dhcp_options.h version.h Makefile
	${CC} ${CFLAGS} -c -o $@ dhcpdump.c

dhcp.o: dhcp.c dhcp.h Makefile
	${CC} ${CFLAGS} -c -o $@ dhcp.c

session.o: session.c session.h dhcp.h Makefile
	${CC} ${CFLAGS} -c -o $@ session.c

tui.o: tui.c tui.h dhcp.h session.h dhcpdump.h version.h Makefile
	${CC} ${CFLAGS} -c -o $@ tui.c

VER:=$(shell grep 'define VERSION' version.h|tr -d '\"'|awk '{print $$3}')
mkotar:
	${MAKE} clean
	-dh_clean
	tar \
		--xform 's,^[.],dhcpdump-${VER},' \
		--exclude ./.git \
		--exclude ./.gitignore \
		--exclude ./debian \
		-Jcvf ../dhcpdump_${VER}.orig.tar.xz .
	-rm -f ../dhcpdump_${VER}.orig.tar.xz.asc
	gpg -a --detach-sign ../dhcpdump_${VER}.orig.tar.xz
	cp -fa ../dhcpdump_${VER}.orig.tar.xz ../dhcpdump-${VER}.tar.xz
	cp -fa ../dhcpdump_${VER}.orig.tar.xz.asc ../dhcpdump-${VER}.tar.xz.asc
