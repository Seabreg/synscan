/*
 * Copyright (C) 2007 - John Anderson, Neil Kettle
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _NET_H
#define _NET_H

#include <netinet/in.h> /* struct in_addr */
#include <sys/types.h>  /* BYTE_ORDER     */

#include "iter.h"
#include "obuf.h"

#define IPV4_INC(a)   ((a) = ntohl(htonl((a))+1))
#define IPV4_MASK(a)  (((uint32_t) -1)>>(a))
#define IPV4_MAX_MASK 32
#define IPV4_HDR_LEN  4 * 5

#define MAX_HOSTNAME  256
#define MAX_PORTLIST  16  /* > 5+1+5 + trailing NUL */

#ifdef IFNAMSIZ
  #define MAX_IFNAMELEN IFNAMSIZE
#else
  #define MAX_IFNAMELEN 16
#endif

#ifndef MAX_IFNAMELEN
  #define MAX_IFNAMELEN 16
#endif

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

typedef int sock_t;

struct ip_hdr_t
{
#if (BYTE_ORDER == LITTLE_ENDIAN)
  uint8_t  ip_hl:4, ip_v:4;
#elif (BYTE_ORDER == BIG_ENDIAN)
  uint8_t  ip_v:4, ip_hl:4;
#else
  #error "Adjust your <asm/byteorder.h> defines"
#endif
  uint8_t  ip_tos;
  uint16_t ip_len;
  uint16_t ip_id;
  uint16_t ip_off;
  uint8_t  ip_ttl;
  uint8_t  ip_p;
  uint16_t ip_sum;

  union {
    struct in_addr ip_src;
    uint32_t ip_src_int;
  } ip_src_t;

  union {
    struct in_addr ip_dst;
    uint32_t ip_dst_int;
  } ip_dst_t;
};

struct tcp_hdr_t {
  uint16_t tcp_sport;
  uint16_t tcp_dport;
  uint32_t tcp_seq;
  uint32_t tcp_ackseq;

#if (BYTE_ORDER == LITTLE_ENDIAN)
  uint8_t res:4,
          doff:4;
#elif (BYTE_ORDER == BIG_ENDIAN)
  uint8_t doff:4,
          res:4;
#else
  #error "Adjust your <asm/byteorder.h> defines"
#endif

  uint8_t  tcp_flags;
  uint16_t tcp_window;
  uint16_t tcp_sum;
  uint16_t tcp_urgptr;
};

struct tcp_phdr_t {
  union {
    struct in_addr ip_src;
    uint32_t ip_src_int;
  } ip_src_t;

  union {
    struct in_addr ip_dst;
    uint32_t ip_dst_int;
  } ip_dst_t;

  uint8_t pad;
  uint8_t p_proto;
  uint16_t p_len;
};

struct iplistv4_t {
  enum ipv4_type_t type;

  union {
    struct {
      union {
        struct in_addr ip;
        uint32_t ip_int;
      } ip_t;

      uint32_t mask;
    };

    struct {
      union {
        struct in_addr ip;
        uint32_t ip_int;
      } lower_t, upper_t;
    };
  };

  struct iplistv4_t *next;
};

struct iplistv4_iter_t {
  enum ipv4_type_t type;
  struct iplistv4_t *list;

  union {
    struct {
      union {
        struct in_addr ip;
        uint32_t ip_int;
      } net_addr_t, broad_addr_t;
    };

    struct {
      union {
        struct in_addr ip;
        uint32_t ip_int;
      } lower_t, upper_t;
    };
  };

  union {
    struct in_addr ip;
    uint32_t ip_int;
  } cur_ipv4_t;
};

struct portlist_t {
  uint32_t lower;
  uint32_t upper;

  struct portlist_t *next;
};

struct portlist_iter_t {
  struct portlist_t *list;
  uint32_t cur_port;
};

struct net_pkt_t {
  struct obuf_t pkt_buf;
  struct obuf_t ppkt_buf;
 
  struct ip_hdr_t *ip_hdr;
  struct tcp_hdr_t *tcp_hdr;
  struct tcp_phdr_t *tcp_phdr;

  uint16_t ip_hdr_len;
  sock_t rsock;
};

char *
rlookup (uint32_t);

char *
nlookup (uint32_t);

uint32_t
lookup (char *);

sock_t
net_sock_init (void);

int
net_get_localip (char *, uint32_t *);

void
net_ipv4_send (struct net_pkt_t *, uint32_t, uint32_t,
               uint16_t, uint16_t);

void
net_ipv4_pkt_init (struct net_pkt_t *, sock_t, uint32_t);

void
net_ipv4_pkt_free (struct net_pkt_t *);

void
net_iplistv4_print (struct iplistv4_t *);

void
net_iplistv4_free (struct iplistv4_t *);

unsigned long long
net_iplistv4_sum (struct iplistv4_t *);

struct iplistv4_t *
net_parse_iplistv4 (char *);

struct iplistv4_t *
net_parse_iplistv4_file (char *, FILE *);

struct iplistv4_iter_t *
net_iplistv4_iter_init (struct iplistv4_iter_t *, struct iplistv4_t *);

unsigned long long
net_iplistv4_iter_sum (struct iplistv4_iter_t *, struct iplistv4_t *);

enum iter_t
net_iplistv4_iter_next (struct iplistv4_iter_t *, struct in_addr *);

void
net_portlist_print (struct portlist_t *);

void
net_portlist_free (struct portlist_t *);

unsigned long long
net_portlist_sum (struct portlist_t *);

struct portlist_t *
net_parse_portlist (char *);

struct portlist_t *
net_parse_portlist_file (char *, FILE *);

struct portlist_iter_t *
net_portlist_iter_init (struct portlist_iter_t *, struct portlist_t *);

unsigned long long
net_portlist_iter_sum (struct portlist_iter_t *, struct portlist_t *);

enum iter_t
net_portlist_iter_next (struct portlist_iter_t *, uint16_t *);

int
net_ipv4_parse_flags (char *, uint8_t *);

#endif
