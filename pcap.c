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

/* pcap.c - Support for the PCAP-format.
 */

#ifdef USE_PCAP

/* POSIX */
#include <arpa/inet.h>

/* libowfat */
#include <buffer.h>

/* Custom */
#include "pcap.h"

void
print_pcap(struct timeval *tv, struct sockaddr_ll *from, char *buf, ssize_t *len, struct options *o)
{
    struct pcap_rec_hdr pkt_hdr;
    struct pcap_sll_hdr sh;
    
    pkt_hdr.ts       = *tv;
    pkt_hdr.incl_len = pkt_hdr.orig_len = *len + sizeof (struct pcap_sll_hdr);

    buffer_put(buffer_1, (char *) &pkt_hdr, sizeof pkt_hdr);

    /* Precede with protocol */
    sh.pkttype = htons(from->sll_pkttype);
    sh.hatype = htons(from->sll_hatype);
    sh.halen = htons(from->sll_halen);

    memcpy(sh.addr, from->sll_addr, from->sll_halen < 8 ? from->sll_halen : 8);
    sh.protocol = from->sll_protocol;
    buffer_put(buffer_1, (char *) &sh, sizeof sh);
    buffer_put(buffer_1, buf, *len);
    buffer_flush(buffer_1);
}

#endif /* USE_PCAP */
