/* 
 * dietsniff - a slim and static network sniffer for Linux
 * Copyright (C) 2005  Hynek Schlawack <hynek@ularx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/* ANSI */
#include <errno.h>
#include <stdio.h> /* only for perror() */
#include <stdlib.h>

/* POSIX */
#include <arpa/inet.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

/* libowfat */
#include <buffer.h>
#include <ip4.h>
#include <ip6.h>
#include <str.h>

/* Custom */
#include "dietsniff.h"
#ifdef USE_REV_RES
#include "rev_res4.h"
#endif /* USE_REV_RES*/
#ifdef USE_PCAP
#include "pcap.h"
#endif /* USE_PCAP */

/* The receiving socket is in the top scope as it might be needed by a
 * signal-handler for statistics.  */
int s;

/*
** error() - generic complain+quit-function. Depends on errno.
*/
void
error(const char *msg)
{
    int rc = errno;

    if (msg) perror(msg);

    exit(rc);
}

/* Security assertions to catch malicious packets. */
inline void SEC_ASSERT(x)
{
    if (__unlikely(!x)) {
	buffer_putsflush(buffer_1, "Security assertion failed! Malicious packets suspected.\n");
	exit(-1);
    }
}

void
print_tcp(struct tcphdr *tcp, ssize_t *len, struct options *o)
{
    SEC_ASSERT(*len >= sizeof (struct tcphdr));

    buffer_puts(buffer_1, " [:");
    buffer_putlong(buffer_1, ntohs(tcp->source));
    buffer_puts(buffer_1, " > :");
    buffer_putlong(buffer_1, ntohs(tcp->dest));
    buffer_puts(buffer_1, "]");
}

void
print_udp(struct udphdr *udp, ssize_t *len, struct options *o)
{
    SEC_ASSERT(*len >= sizeof (struct udphdr));

    buffer_puts(buffer_1, " [:");
    buffer_putlong(buffer_1, ntohs(udp->source));
    buffer_puts(buffer_1, " > :");
    buffer_putlong(buffer_1, ntohs(udp->dest));
    buffer_puts(buffer_1, "]");
}

#define ADDR42STR(str, ip) (str[fmt_ip4(str, (char *) &ip)] = '\0', str)

void
print_ip(struct iphdr *ip, ssize_t *len, struct options *o)
{
    buffer_puts(buffer_1, "[ipv4] ");
    char addr[IP4_FMT] = { 0 };
#ifdef USE_REV_RES
    char *name;

    SEC_ASSERT(*len >= sizeof (struct iphdr));

    if (o->no_rev_res) {
#endif /* USE_REV_RES */
	buffer_puts(buffer_1, ADDR42STR(addr, ip->saddr)); 
	buffer_puts(buffer_1, " > ");
	buffer_puts(buffer_1, ADDR42STR(addr, ip->daddr));
#ifdef USE_REV_RES
    } else {
	name = addr2name4(ip->saddr);
	buffer_puts(buffer_1, str_len(name) ? name : ADDR42STR(addr, ip->saddr));
	buffer_puts(buffer_1, " > ");
	name = addr2name4(ip->daddr);
	buffer_puts(buffer_1, str_len(name) ? name : ADDR42STR(addr, ip->daddr));
    }
#endif /* USE_REV_RES */

    /* Handle flags */
    if (o->verbose) {
	buffer_puts(buffer_1, " [");
	if (ip->frag_off) buffer_puts(buffer_1, "DF, ");
	buffer_puts(buffer_1, "LEN=");
	buffer_putlong(buffer_1, ip->tot_len);
	buffer_puts(buffer_1, ", TTL=");
	buffer_putlong(buffer_1, ip->ttl);
	buffer_puts(buffer_1, ", ID=");
	buffer_putlong(buffer_1, ip->id);
	buffer_puts(buffer_1, "]");
    }

    switch(ip->protocol) {
    case 0x1:
	buffer_puts(buffer_1, " [icmpv4]");
	break;
    case 0x2:
	buffer_puts(buffer_1, " [igmpv4]");
	break;
    case 0x6:
	buffer_puts(buffer_1, " [tcp]");
	print_tcp((void *) ip+(ip->ihl * sizeof(long)), len, o);
	break;
    case 0x11:
	buffer_puts(buffer_1, " [udp]");
	print_udp((void *) ip+(ip->ihl * sizeof(long)), len, o);
	break;
    default:
	buffer_puts(buffer_1, " [unknown]");
	break;
    }
}

void
print_arp(struct arphdr *arp, ssize_t *len, struct options *o)
{
    SEC_ASSERT(*len >= sizeof (struct arphdr));
    buffer_puts(buffer_1, "[arp] ");
}

void
print_rarp(struct arphdr *arp, ssize_t *len, struct options *o)
{
    SEC_ASSERT(*len >= sizeof (struct arphdr));
    buffer_puts(buffer_1, "[rarp] ");
}

void
print_frame(struct sockaddr_ll *from, char *buf, ssize_t *len, struct options *o)
{    
    switch (ntohs(from->sll_protocol)) {
	/* IP */
    case ETH_P_IP:
	print_ip((struct iphdr *) buf, len, o);
	break;
	/* PPPoE */
    case ETH_P_PPP_DISC:
    case ETH_P_PPP_SES:
	buffer_puts(buffer_1, "[PPPoE]");
	break;
	/* ARP */
    case ETH_P_ARP:
	print_arp((struct arphdr *) buf, len, o);
	break;
	/* RARP */
    case ETH_P_RARP:
	print_arp((struct arphdr *) buf, len, o);
	break;
    default:
	buffer_puts(buffer_1, "[unknown frametype 0x");
	buffer_putxlong(buffer_1, ntohs(from->sll_protocol));
	buffer_puts(buffer_1, "]");
    }
	
    buffer_putnlflush(buffer_1);
}

/* Caching netdev-name-lookups */
#define MAX_NETDEVS 256 /* Hardcode */
static char *mappings[MAX_NETDEVS];
static inline char *
i2n(int i)
{
    if (__unlikely(!mappings[i])) {
	mappings[i] = malloc(IFNAMSIZ);
	if (__unlikely(if_indextoname(i, mappings[i]) == NULL)) {
	    error("Can't convert if-index to name");
	}
    }

    return mappings[i];
}

static inline void
buffer1_put2dec(const unsigned char x) {
    char c[2];
    c[0]=(x/10)+'0';
    c[1]=(x%10)+'0';
    buffer_put(buffer_1,c,2);
}

#ifdef USE_PACKET_STATISTICS
void 
sig_onexit(int num)
{
    struct tpacket_stats stats;
    socklen_t stats_len = sizeof(stats);

    if (getsockopt(s, SOL_PACKET, PACKET_STATISTICS, (char *) &stats, &stats_len) == 0) {
        buffer_puts(buffer_2, "\nPacket Statistics\n");
        buffer_puts(buffer_2, "    Kernel received    : ");
        buffer_putlong(buffer_2, stats.tp_packets);
        buffer_puts(buffer_2, "\n    Kernel dropped     : ");
        buffer_putlong(buffer_2, stats.tp_drops);
        buffer_puts(buffer_2, "\n    dietsniff processed: ");
        buffer_putlong(buffer_2, (stats.tp_packets - stats.tp_drops));
        buffer_puts(buffer_2, " (~");
        buffer_putlong(buffer_2, stats.tp_packets ? ((((double) (stats.tp_packets - stats.tp_drops)) / stats.tp_packets) * 100) : 100);
        buffer_puts(buffer_2, "%)\n");
        buffer_putnlflush(buffer_2);
    }
    exit(EXIT_SUCCESS);
}
#endif /* USE_PACKET_STATISTICS */


int
main(int argc, char **argv)
{
    char buf[BUF_SIZE+1];
    struct options o;
    int option;
    struct sockaddr_ll from;
    socklen_t fromlen;
    int lo;

    byte_zero(&o, sizeof(struct options));
    o.pkts_todo = -1;

    while ((option = getopt(argc, argv, PCAP_OPT REV_RES_OPT "hvc:i:")) != -1) {
#ifdef USE_PCAP
	static const struct pcap_hdr hdr = { PCAP_MAGIC, 2, 4, 0, 0, BUF_SIZE, 113 /* DLT_LINUX_SLL - Linux cooked sockets */ };
#endif /* USE_PCAP */

	switch (option) {
	case 'c':
	    errno = 0; /* strtoul doesn't reset errno and uses two
			* return-codes as error-indicators */
	    o.pkts_todo = strtoul(optarg, NULL, 10);
	    if (__unlikely(errno == ERANGE || errno == EINVAL))
		error("Invalid count-argument");
	    break;

	case 'h':
	    buffer_puts(buffer_1, VER_STRING"\n");
	    buffer_puts(buffer_1, "Usage: dietsniff"
			" [-c count]"

			" [-i interface]"
#ifdef USE_REV_RES
			" -" REV_RES_OPT
#endif /* USE_REV_RES */
#ifdef USE_PCAP
			" -" PCAP_OPT
#endif /* USE_PCAP */
			" -v");
	    buffer_putnlflush(buffer_1);

	    exit(0);
	    break;

	case 'i':
	    o.filter.dev = strdup(optarg);
	    break;

#ifdef USE_REV_RES
	case 'n':
	    o.no_rev_res = 1;
	    break;
#endif /* USE_REV_RES */

#ifdef USE_PCAP
	case 'p':
	    o.pcap = 1;

	    /* Write out file-header - no flush as it gets flushed
	     * with the first packet. */
	    buffer_put(buffer_1, (char *) &hdr, sizeof hdr);
	    break;
#endif /* USE_PCAP */

	case 'v':
	    o.verbose = 1;
	    break;
	}
    }

    if ((s = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) == -1) error("Creating socket failed");

#ifdef USE_PACKET_STATISTICS
    signal(SIGINT, sig_onexit);
#endif /* USE_PACKET_STATISTICS */

    fromlen = sizeof(from);

    if (o.filter.dev) {
	from.sll_family = AF_PACKET;
	from.sll_protocol = htons(ETH_P_ALL);
	from.sll_ifindex = if_nametoindex(o.filter.dev);
	if (bind(s, (struct sockaddr *) &from, fromlen) == -1) error("Binding to interface failed");
    }

    /* No error-handling on purpose. If lo doesn't exist (-> -1) we
     * don't leave out packets. */
    lo = if_nametoindex("lo");

    while (__likely(o.pkts_todo)) {
	ssize_t len;
	struct tm *tm;
	struct timeval tv;
	char *name;

	if ((len = recvfrom(s, buf, BUF_SIZE, 0, (struct sockaddr *) &from, &fromlen)) == -1)
	    error("Receiving frame failed");

	/* Skip duplicate packets on loopback */
	if (from.sll_ifindex == lo && from.sll_pkttype != PACKET_OUTGOING)
	    continue;

	name = i2n(from.sll_ifindex);

	ioctl(s, SIOCGSTAMP, &tv);

#ifdef USE_PCAP
	if (o.pcap) {
	    print_pcap(&tv, &from, buf, &len, &o);
	} else {
#endif /* USE_PCAP */
	    tm = localtime(&tv.tv_sec);

	    buffer1_put2dec(tm->tm_hour);
	    buffer_puts(buffer_1, ":");
	    buffer1_put2dec(tm->tm_min);
	    buffer_puts(buffer_1, ":");
	    buffer1_put2dec(tm->tm_sec);
	    buffer_puts(buffer_1, ".");
	    buffer1_put2dec(tv.tv_usec / 10000);
	    buffer1_put2dec((tv.tv_usec / 1000) % 100);
	    buffer1_put2dec((tv.tv_usec / 10) % 100);
	    buffer_puts(buffer_1, " ");

	    buffer_puts(buffer_1, "[");
	    buffer_puts(buffer_1, name);
	    buffer_puts(buffer_1, "] ");
	    print_frame(&from, buf, &len, &o);

#ifdef USE_PCAP
	}
#endif /* USE_PCAP */

	/* If a count has been specified, decrement. */
	if (__unlikely(o.pkts_todo != -1)) {
	    o.pkts_todo--;
	}
    }
	
    return 0;
}
