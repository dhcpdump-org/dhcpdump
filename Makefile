CFLAGS+=${CPPFLAGS}
CFLAGS+=-Wall -Wextra -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 -g -O3 -fPIE
LDFLAGS+=-g -Wl,-z,relro -Wl,-z,now -fPIE -pie
LIBS+=-lpcap

ifeq ($(shell uname -s),Darwin)
LDFLAGSTODROP:=-Wl,-z,relro -Wl,-z,now
LDFLAGS:=$(filter-out $(LDFLAGSTODROP),$(LDFLAGS))
endif

OBJS=main.o dhcpdump.o dhcp.o session.o

all: dhcpdump dhcpdump.8

clean:
	-rm -f ${OBJS} dhcpdump dhcpdump.8

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

main.o: main.c dhcpdump.h dhcp.h session.h version.h Makefile
	${CC} ${CFLAGS} -c -o $@ main.c

dhcpdump.o: dhcpdump.c dhcpdump.h dhcp_options.h version.h Makefile
	${CC} ${CFLAGS} -c -o $@ dhcpdump.c

dhcp.o: dhcp.c dhcp.h Makefile
	${CC} ${CFLAGS} -c -o $@ dhcp.c

session.o: session.c session.h dhcp.h Makefile
	${CC} ${CFLAGS} -c -o $@ session.c

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
