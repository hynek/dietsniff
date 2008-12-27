#
# User-tweakable options
#

FEATURES=-DUSE_REV_RES -DUSE_PCAP -DUSE_PACKET_STATISTICS

prefix=/usr/local
SBINDIR=${prefix}/sbin
MAN1DIR=${prefix}/man/man1

INSTALL=install
CC=diet -Os gcc
LIBS=-lowfat
CFLAGS=-Wall -I /usr/include/libowfat $(FEATURES)
LDFLAGS=-s

#
# Building rules
#

dietsniff: main.o rev_res4.o pcap.o
	$(CC) $(CFLAGS)  -o $@ $^ $(LIBS)
	strip dietsniff

main.o: main.c dietsniff.h rev_res4.h
rev_res4.o: rev_res4.c rev_res4.h dietsniff.h
pcap.o: pcap.c pcap.h

#
# PHONY targets
#

.PHONY : clean install
clean:
	- rm *.o dietsniff

install: dietsniff
	$(INSTALL) -d $(DESTDIR)$(MAN1DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 dietsniff $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 644 man/dietsniff.1 $(DESTDIR)$(MAN1DIR)/dietsniff.1