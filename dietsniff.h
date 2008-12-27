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

#ifndef DIETSNIFF_H
#define DIETSNIFF_H

#define VERSION "0.4"
#define VER_STRING "dietsniff " VERSION " (c) 2005-2008 Hynek Schlawack"

#define BUF_SIZE (65536-1)

struct filter {
    char *dev;
};

#ifndef __likely
#define __likely(x)    __builtin_expect(!!(x), 1)
#endif
#ifndef __unlikely
#define __unlikely(x)  __builtin_expect(!!(x), 0)
#endif

struct options {
    struct filter filter;
#ifdef USE_REV_RES
    short no_rev_res;
#endif /* USE_REV_RES */
    short verbose;
#ifdef USE_PCAP
    short pcap;
#endif /* USE_PCAP */
    unsigned long pkts_todo;
};

#ifdef USE_PCAP
#define PCAP_OPT "p"
#else /* USE_PCAP */
#define PCAP_OPT ""
#endif /* USE_PCAP */

#ifdef USE_REV_RES
#define REV_RES_OPT "n"
#else /* USE_REV_RES */
#define REV_RES_OPT ""
#endif /* USE_REV_RES */

void error(const char *msg);

#ifdef USE_PACKET_STATISTICS
/* Following defined in linux/if_packet.h */
#define PACKET_STATISTICS               6

struct tpacket_stats
{
    unsigned int    tp_packets;
    unsigned int    tp_drops;
};

#endif /* USE_PACKET_STATISTICS */

#endif /* DIETSNIFF_H */
