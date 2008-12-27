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

/* rev_res4.c - Contains everything concerning reverse resolution of
 * IPv4-addresses.
 */

#ifdef USE_REV_RES

/* ANSI */
#include <stdlib.h>

/* POSIX */
#include <errno.h>

/* libowfat */
#include <dns.h>
#include <stralloc.h>

/* Custom */
#include "dietsniff.h"

#define HASHSIZE 257

struct node {
    struct node *n;
    int addr;
    char *hn;
};

static inline int
hash(int x)
{
    return x % HASHSIZE;
}

static struct node *hashtable[HASHSIZE];

static void
append(int addr, char *hn)
{
    int q = hash(addr);
    struct node *n = malloc(sizeof(struct node));

    if (!n) error("Allocation of memory failed");

    n->n = NULL;
    n->addr = addr;
    n->hn = hn;

    if (__unlikely(hashtable[q])) {
	struct node *p = hashtable[q];

	for (;p->n; p = p->n);

	p->n = n;
    } else {
	hashtable[q] = n;
    }
}

char *
addr2name4(int addr)
{
    struct node *n = hashtable[hash(addr)];

    for (;n; n = n->n) {
	if (__unlikely(addr == n->addr)) {
	    break;
	}
    }

    if (__likely(n)) {
	return n->hn;
    } else {
	stralloc out = { 0 };

	if (dns_name4(&out, (char *) &addr) == -1) error("Reverse resolving failed");

	append(addr, out.s);

	return out.s;
    }
}

#endif /* REV_RES */
