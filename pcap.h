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

#ifndef PCAP_H
#define PCAP_H

/* POSIX */
#include <netpacket/packet.h>
#include <time.h>

#include "dietsniff.h"

#define PCAP_MAGIC 0xa1b2c3d4

struct pcap_hdr {
    unsigned long       magic;		/* magic */
    unsigned short	version_major;	/* major version number */
    unsigned short	version_minor;	/* minor version number */
    unsigned long	thiszone;	/* GMT to local correction */
    unsigned long	sigfigs;	/* accuracy of timestamps */
    unsigned long	snaplen;	/* max length of captured packets, in octets */
    unsigned long	network;	/* data link type */
} __attribute__((__packed__));

struct pcap_rec_hdr {
    struct timeval      ts;             /* timestamp */
    unsigned long	incl_len;	/* number of octets of packet saved in file */
    unsigned long	orig_len;	/* actual length of packet */
} __attribute__((__packed__));

struct pcap_sll_hdr {                   /* Fields ressemble those from "struct sockaddr_ll" */
    unsigned short pkttype;
    unsigned short hatype;
    unsigned short halen;
    char addr[8];
    unsigned short protocol;
} __attribute__((__packed__));

void print_pcap(struct timeval *, struct sockaddr_ll *, char *, ssize_t *, struct options *);

#endif /* PCAP_H */
