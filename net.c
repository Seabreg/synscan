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

#include <stdio.h>
#include <stdlib.h>

#include "config.h"

#ifdef DEBUG
#include <assert.h>
#endif

#include <arpa/inet.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <netdb.h>
#include <netinet/in.h>

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <sys/socket.h>

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#include <net/if.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "net.h"
#include "obuf.h"
#include "synscan.h"

char *
rlookup (uint32_t ip)
{
  static char hostname[MAX_HOSTNAME];
  char *host;
  struct hostent *hostp;
  struct sockaddr_in sock_addr;

  sock_addr.sin_addr.s_addr = ip;
  hostp =
    gethostbyaddr ((char *) &sock_addr.sin_addr, sizeof sock_addr.sin_addr,
                   AF_INET);

  if (hostp == NULL)
    {
      struct in_addr insock_addr;

      insock_addr.s_addr = ip;
      host = inet_ntoa (insock_addr);
    }
  else
    host = hostp->h_name;

  strncpy (hostname, host, sizeof hostname - 1);
  hostname[sizeof hostname - 1] = '\0';

  return (hostname);
}

char *
nlookup (uint32_t ip)
{
  static char hostname[MAX_HOSTNAME];
  struct in_addr insock_addr;

  insock_addr.s_addr = ip;
  strncpy (hostname, inet_ntoa (insock_addr), sizeof hostname - 1);
  hostname[sizeof hostname - 1] = '\0';

  return (hostname);
}

uint32_t
lookup (char *hostname)
{
  struct hostent *hostp;
  uint32_t address;

  if ((address = inet_addr (hostname)) != -1)
    return (address);

  if ((hostp = gethostbyname (hostname)) == NULL)
    return -1;

  memcpy (&address, hostp->h_addr, hostp->h_length);

  return (address);
}

sock_t
net_sock_init (void)
{
  sock_t sock;

  sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock == -1)
    return (-1);

#ifdef MACOS
  {
    int true = 1;
    setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &true, sizeof true);
  }
#endif

  return (sock);
}

static uint16_t
net_ip_sum (const uint16_t *ptr, int len)
{
  register int sum = 0;

  while (len > 1)
    {
      sum += *ptr++;
      len -= 2;
    }

  if (len == 1)
    sum += *((unsigned char *) ptr);

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (~sum);
}

static void
net_ipv4_send_segment (struct net_pkt_t *pkt, struct ip_hdr_t *ip_hdr,
                       struct tcp_hdr_t *tcp_hdr, struct tcp_phdr_t *tcp_phdr)
{
  void *pbuf;
  struct sockaddr_in sin;

  pbuf = tcp_phdr;
  memcpy (pbuf + sizeof *tcp_phdr, tcp_hdr, sizeof *tcp_hdr);
  tcp_hdr->tcp_sum =
    net_ip_sum ((uint16_t *) pbuf, sizeof *tcp_phdr + sizeof *tcp_hdr);

  pbuf = ip_hdr;
  ip_hdr->ip_sum = net_ip_sum ((uint16_t *) pbuf, sizeof *ip_hdr);

  sin.sin_family = AF_INET;
  sin.sin_port = tcp_hdr->tcp_dport;
  sin.sin_addr = ip_hdr->ip_dst_t.ip_dst;

#ifdef DEBUG_CHECKSUM
  printf ("%04x %04x\n", ip_hdr->ip_sum, tcp_hdr->tcp_sum);
#endif

  sendto (pkt->rsock, pbuf, sizeof *ip_hdr + sizeof *tcp_hdr, 0,
          (struct sockaddr *) &sin, sizeof sin);
}

void
net_ipv4_send (struct net_pkt_t *pkt, uint32_t srcip, uint32_t dstip,
               uint16_t sport, uint16_t dport)
{
  struct ip_hdr_t *ip_hdr;
  struct tcp_hdr_t *tcp_hdr;
  struct tcp_phdr_t *tcp_phdr;

  ip_hdr = pkt->ip_hdr;
  tcp_hdr = pkt->tcp_hdr;
  tcp_phdr = pkt->tcp_phdr;

  /* update variable header values */
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_src_t.ip_src_int = srcip;
  ip_hdr->ip_dst_t.ip_dst_int = dstip;

  tcp_hdr->tcp_sum = 0;
  tcp_hdr->tcp_sport = htons (sport);
  tcp_hdr->tcp_dport = htons (dport);

  tcp_phdr->ip_src_t.ip_src_int = srcip;
  tcp_phdr->ip_dst_t.ip_dst_int = dstip;

  net_ipv4_send_segment (pkt, ip_hdr, tcp_hdr, tcp_phdr);
}

static void
net_ipv4_pkt_init_headers (struct ip_hdr_t *ip_hdr)
{
  uint32_t rlong;
  uint16_t rshrt;

  rlong = rand ();
  rshrt = rlong & 0xffff;
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_tos = 0;
#ifndef HAVE_CRUFTY_IPLENOFF
  ip_hdr->ip_len = htons (sizeof *ip_hdr + sizeof (struct tcp_hdr_t));
  ip_hdr->ip_off = htons (0);
#else
  ip_hdr->ip_len = sizeof *ip_hdr + sizeof (struct tcp_hdr_t);
  ip_hdr->ip_off = 0;
#endif
  ip_hdr->ip_id = rshrt;
  ip_hdr->ip_ttl = 30;
  ip_hdr->ip_p = IPPROTO_TCP;
}

static void
net_tcp_pkt_init_headers (struct tcp_hdr_t *tcp_hdr,
                          struct tcp_phdr_t *tcp_phdr, uint32_t tcp_flags)
{
  uint32_t rlong;
  uint16_t rshrt;

  rlong = rand ();
  rshrt = rlong & 0xffff;
  tcp_hdr->tcp_seq = rlong;
  tcp_hdr->tcp_ackseq = rlong;
  tcp_hdr->doff = sizeof *tcp_hdr / 4;
  tcp_hdr->tcp_flags = tcp_flags;
  tcp_hdr->tcp_window = rshrt;
  tcp_hdr->tcp_urgptr = rshrt;

  tcp_phdr->pad = 0;
  tcp_phdr->p_proto = IPPROTO_TCP;
  tcp_phdr->p_len = htons (sizeof *tcp_hdr);
}

void
net_ipv4_pkt_init (struct net_pkt_t *pkt, sock_t rsock, uint32_t tcp_flags)
{
  int buflen;

  if (pkt == NULL)
    return;

  buflen = sizeof (struct ip_hdr_t) + sizeof (struct tcp_hdr_t);
  obuf_allocate (&pkt->pkt_buf, buflen);
  memset (pkt->pkt_buf.buf, 0, buflen);

  buflen = sizeof (struct tcp_phdr_t) + sizeof (struct tcp_hdr_t);
  obuf_allocate (&pkt->ppkt_buf, buflen);
  memset (pkt->ppkt_buf.buf, 0, buflen);

  pkt->ip_hdr = pkt->pkt_buf.buf;
  pkt->tcp_hdr = pkt->pkt_buf.buf + sizeof (struct ip_hdr_t);
  pkt->tcp_phdr = pkt->ppkt_buf.buf;
  pkt->rsock = rsock;

  net_ipv4_pkt_init_headers (pkt->ip_hdr);
  net_tcp_pkt_init_headers (pkt->tcp_hdr, pkt->tcp_phdr, tcp_flags);
}

void
net_ipv4_pkt_free (struct net_pkt_t *pkt)
{
  if (pkt == NULL)
    return;

  obuf_free (&pkt->pkt_buf);
  obuf_free (&pkt->ppkt_buf);
}

#ifdef HAVE_IFADDRS_H
static int
net_get_localip_getifaddrs (char *if_name, uint32_t *ip_addr)
{
  struct ifaddrs *ifa_head;
  int result;

  result = SYN_ERR;
  if (getifaddrs (&ifa_head) == 0)
    {
      struct ifaddrs *ifa_cur;

      ifa_cur = ifa_head;
      for (ifa_cur = ifa_head; ifa_cur; ifa_cur = ifa_cur->ifa_next)
        {
          if (ifa_cur->ifa_name != NULL && ifa_cur->ifa_addr != NULL)
            {
              if (strcmp (if_name, (char *) ifa_cur->ifa_name) != 0 ||
                  ifa_cur->ifa_addr->sa_family != AF_INET ||
                  !(ifa_cur->ifa_flags & IFF_UP))
                continue;

              memcpy (ip_addr,
                      &(((struct sockaddr_in *) ifa_cur->ifa_addr)->sin_addr),
                      sizeof *ip_addr);
              result = SYN_OK;
              break;
            }
        }

      freeifaddrs (ifa_head);
    }

  return (result);
}
#endif

#ifdef HAVE_SYS_IOCTL_H
#define MAX_INTERFACES 16

static int
net_get_localip_ioctl (char *if_name, uint32_t *ip_addr)
{
  struct ifreq ifr[MAX_INTERFACES];
  struct ifconf ifc;
  int i, if_count, result, sock;

  sock = socket (PF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    return (-1);

  memset (&ifc, 0, sizeof ifc);
  ifc.ifc_buf = (char *) &ifr;
  ifc.ifc_len = sizeof ifr;

  if (ioctl (sock, SIOCGIFCONF, &ifc) == -1)
    return (SYN_ERR);

  result = SYN_ERR;
  if_count = ifc.ifc_len / sizeof (struct ifreq);
  for (i = 0; i < if_count; i++)
    {
      if (ioctl (sock, SIOCGIFADDR, &ifr[i]) == -1)
        continue;
      if (ioctl (sock, SIOCGIFFLAGS, &ifr[i]) == -1)
        continue;

      if (strcmp (if_name, (char *) ifr[i].ifr_name) != 0 ||
          !(ifr[i].ifr_flags & IFF_UP))
        continue;

      memcpy (ip_addr, &(((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr),
              sizeof *ip_addr);
      result = SYN_OK;
      break;
    }

  if (close (sock) != 0)
    return (SYN_ERR);

  return (result);
}
#endif

int
net_get_localip (char *if_name, uint32_t *ip_addr)
{
#ifdef HAVE_SYS_IOCTL_H
  if (net_get_localip_ioctl (if_name, ip_addr) != SYN_ERR)
    return (SYN_OK);
#endif

#ifdef HAVE_IFADDRS_H
  if (net_get_localip_getifaddrs (if_name, ip_addr) != SYN_ERR)
    return (SYN_OK);
#endif

  return (SYN_ERR);
}

void
net_iplistv4_print (struct iplistv4_t *list)
{
  while (list != NULL)
    {
      if (list->type == IPV4_TYPE_NET)
        {
          fprintf (stdout, "    %s/%d\n", nlookup (list->ip_t.ip_int),
                   list->mask);
        }
      else
        {
          char lbuf[MAX_HOSTNAME], ubuf[MAX_HOSTNAME];

          memcpy (lbuf, nlookup (list->lower_t.ip_int), sizeof lbuf);
          memcpy (ubuf, nlookup (list->upper_t.ip_int), sizeof ubuf);
          fprintf (stdout, "    %s-%s\n", lbuf, ubuf);
        }

      list = list->next;
    }
}

static struct iplistv4_t *
net_iplistv4_add_range (struct iplistv4_t *head, uint32_t lower, uint32_t upper)
{
  struct iplistv4_t *ptr;
  uint32_t lower_n, upper_n;

  lower_n = htonl (lower);
  upper_n = htonl (upper);

  if (upper_n < lower_n)
    return (NULL);

  ptr = malloc (sizeof (struct iplistv4_t));
  if (ptr == NULL)
    fatal ("%s: net_iplistv4_add_range: out of memory allocating %d-bytes\n",
           arg_progname, sizeof (struct iplistv4_t));

  ptr->next = head;
  ptr->type = IPV4_TYPE_RANGE;
  ptr->lower_t.ip_int = lower;
  ptr->upper_t.ip_int = upper;

  return (ptr);
}

static struct iplistv4_t *
net_iplistv4_add_net (struct iplistv4_t *head, uint32_t ip, uint32_t mask)
{
  struct iplistv4_t *ptr;

  if (mask > IPV4_MAX_MASK)
    return (NULL);

  ptr = malloc (sizeof (struct iplistv4_t));
  if (ptr == NULL)
    fatal ("%s: net_iplistv4_add_net: out of memory allocating %d-bytes\n",
           arg_progname, sizeof (struct iplistv4_t));

  ptr->next = head;
  ptr->type = IPV4_TYPE_NET;
  ptr->ip_t.ip_int = ip;
  ptr->mask = mask;

  return (ptr);
}

void
net_iplistv4_free (struct iplistv4_t *head)
{
  while (head != NULL)
    {
      struct iplistv4_t *ptr;

      ptr = head->next;
      free (head);
      head = ptr;
    }
}

unsigned long long
net_iplistv4_sum (struct iplistv4_t *head)
{
  unsigned long long cur_sum;

  if (head == NULL)
    return (0);

  cur_sum = 0;
  while (head != NULL)
    {
      if (head->type == IPV4_TYPE_NET)
        {
          if (head->mask < IPV4_MAX_MASK)
            cur_sum += IPV4_MASK (head->mask);
        }
      else
        {
          uint32_t lower_n, upper_n;

          lower_n = htonl (head->lower_t.ip_int);
          upper_n = htonl (head->upper_t.ip_int);
          cur_sum += upper_n - lower_n;
        }

      cur_sum++;
      head = head->next;
    }

  return (cur_sum);
}

static uint32_t
net_parse_ipv4 (char *host, struct in_addr *addr)
{
  uint32_t cur_addr, blks_num, i;
  struct in_addr o_addr;
  char *blks[4], *ptr;

  if (host == NULL || addr == NULL)
    return (SYN_ERR);

  for (ptr = strtok (host, "."), i = 0; ptr != NULL && i < 4;
       ptr = strtok (NULL, "."), i++)
    {
      blks[i] = ptr;
    }

  if (ptr != NULL)
    return (SYN_ERR);

  blks_num = i;

  for (cur_addr = i = 0; i < blks_num; i++)
    {
      int ip_blk;

      ip_blk = atoi (blks[i]);
      if (ip_blk < 0 || ip_blk > 255)
        return (SYN_ERR);

      cur_addr |= (ip_blk << (24 - (i * 8)));
    }

  o_addr.s_addr = htonl (cur_addr);
  memcpy (addr, &o_addr, sizeof o_addr);

  return (SYN_OK);
}

struct iplistv4_t *
net_parse_iplistv4 (char *arg)
{
  struct iplistv4_t *head;
  char *bgn, *end;
  char host[MAX_HOSTNAME];

  /* empty the list */
  head = NULL;

  bgn = arg;
  do
    {
      struct iplistv4_t *cur_head;
      char *ptr;
      uint32_t mask;
      int len, result;

      end = strchr (bgn, ',');
      if (end)
        len = end - bgn;
      else
        len = strlen (bgn);

      if (len < 0 || len > sizeof host - 1)
        goto cleanup;

      strncpy (host, bgn, len);
      host[len] = '\0';

      if ((ptr = strchr (host, '-')))
        {
          struct in_addr lower_addr, upper_addr;

          /* ipv4 network range */
          *ptr++ = '\0';  /* remove '-' */
          result = net_parse_ipv4 (host, &lower_addr);
          if (result != SYN_OK)
            goto cleanup;

          result = net_parse_ipv4 (ptr, &upper_addr);
          if (result != SYN_OK)
            goto cleanup;

          if ((cur_head = net_iplistv4_add_range (head, lower_addr.s_addr,
                                                        upper_addr.s_addr)) == NULL)
            goto cleanup;
        }
      else
        {
          struct in_addr addr;

          /* ipv4 network block */
          if ((ptr = strchr (host, '/')))
            {
              *ptr++ = '\0';  /* remove '/' */
              if (strlen (ptr) != strspn (ptr, "0123456789"))
                goto cleanup;

              mask = atoi (ptr);
            }
          else
            mask = IPV4_MAX_MASK;

          result = net_parse_ipv4 (host, &addr);
          if (result != SYN_OK)
            goto cleanup;

          if ((cur_head = net_iplistv4_add_net (head, addr.s_addr, mask)) == NULL)
            goto cleanup;
        }

      head = cur_head;

      bgn = end + 1;
    }
  while (end != NULL);

  return (head);

cleanup:
  net_iplistv4_free (head);
  return (NULL);
}

struct iplistv4_t *
net_parse_iplistv4_file (char *filen, FILE *filen_fp)
{
  struct iplistv4_t *head;
  char host[MAX_HOSTNAME];

  /* empty the list */
  head = NULL;

  while (fgets (host, sizeof host, filen_fp))
    {
      struct iplistv4_t *cur_head;
      char *ptr;
      uint32_t mask;
      int result;

      /* chomp the newline */
      ptr = host + strlen (host) - 1;
      while (ptr >= host && (*ptr == '\r' || *ptr == '\n'))
        {
          *ptr = '\0';
          if (ptr > host)
            ptr--;
        }

      /* blank line */
      if (ptr == host)
        continue;

      if ((ptr = strchr (host, '-')))
        {
          struct in_addr lower_addr, upper_addr;

          /* ipv4 network range */
          *ptr++ = '\0';  /* remove '-' */
          result = net_parse_ipv4 (host, &lower_addr);
          if (result != SYN_OK)
            goto cleanup;

          result = net_parse_ipv4 (ptr, &upper_addr);
          if (result != SYN_OK)
            goto cleanup;

          if ((cur_head = net_iplistv4_add_range (head, lower_addr.s_addr,
                                                        upper_addr.s_addr)) == NULL)
            goto cleanup;
        }
      else
        {
          struct in_addr addr;

          /* ipv4 network block */
          if ((ptr = strchr (host, '/')))
            {
              *ptr++ = '\0';  /* remove '/' */
              if (strlen (ptr) != strspn (ptr, "0123456789"))
                goto cleanup;

              mask = atoi (ptr);
            }
          else
            mask = IPV4_MAX_MASK;

          result = net_parse_ipv4 (host, &addr);
          if (result != SYN_OK)
            goto cleanup;

          if ((cur_head = net_iplistv4_add_net (head, addr.s_addr, mask)) == NULL)
            goto cleanup;
        }

      head = cur_head;
    }

  return (head);

cleanup:
  net_iplistv4_free (head);
  return (NULL);
}

struct iplistv4_iter_t *
net_iplistv4_iter_init (struct iplistv4_iter_t *iter, struct iplistv4_t *list)
{
#ifdef DEBUG
  if (iter == NULL || list == NULL)
    return (NULL);
#endif

  iter->list = list;
  iter->type = list->type;

  if (list->type == IPV4_TYPE_NET)
    {
      uint32_t net_addr, broad_addr;
      uint32_t mask;

      net_addr = htonl (list->ip_t.ip_int);
      broad_addr = htonl (list->ip_t.ip_int);

      if (list->mask < IPV4_MAX_MASK)
        {
          mask = IPV4_MASK (list->mask);
          net_addr &= ~mask;
          broad_addr |= mask;
        }

      iter->net_addr_t.ip_int = ntohl (net_addr);
      iter->broad_addr_t.ip_int = ntohl (broad_addr);
      iter->cur_ipv4_t.ip_int = iter->net_addr_t.ip_int;
    }
  else if (list->type == IPV4_TYPE_RANGE)
    {
      iter->lower_t.ip_int = list->lower_t.ip_int;
      iter->upper_t.ip_int = list->upper_t.ip_int;
      iter->cur_ipv4_t.ip_int = iter->lower_t.ip_int;
    }
  else
    fatal ("%s: net_iplistv4_iter_init: unknown ipv4 iter type: %d\n",
           arg_progname, list->type);

  return (iter);
}

unsigned long long
net_iplistv4_iter_sum (struct iplistv4_iter_t *iter, struct iplistv4_t *list)
{
  unsigned long long cur_sum;
  struct iplistv4_t *head;

#ifdef DEBUG
  if (iter == NULL || list == NULL)
    return (NULL);
#endif

  cur_sum = 0;
  head = list;

  while (head != NULL && head != iter->list)
    {
      if (head->type == IPV4_TYPE_NET)
        {
          if (head->mask < IPV4_MAX_MASK)
            cur_sum += IPV4_MASK (head->mask);
        }
      else
        {
          uint32_t lower_n, upper_n;

          lower_n = htonl (head->lower_t.ip_int);
          upper_n = htonl (head->upper_t.ip_int);
          cur_sum += upper_n - lower_n;
        }

      cur_sum++;
      head = head->next;
    }

  if (head == iter->list)
    {
      uint32_t lower_n, upper_n;

      if (head->type == IPV4_TYPE_NET)
        {
          lower_n = htonl (head->ip_t.ip_int);

          if (head->mask < IPV4_MAX_MASK)
            {
              uint32_t mask = IPV4_MASK (head->mask);
              lower_n &= ~mask;
            }

          upper_n = htonl (iter->cur_ipv4_t.ip_int);
        }
      else
        {
          lower_n = htonl (head->lower_t.ip_int);
          upper_n = htonl (iter->cur_ipv4_t.ip_int);
        }

      cur_sum += (upper_n - lower_n);
    }

  return (cur_sum);
}

enum iter_t
net_iplistv4_iter_next (struct iplistv4_iter_t *iter, struct in_addr *out)
{
  uint32_t cur_n, upper_n;

#ifdef DEBUG
  if (iter == NULL)
    return (ITER_ERROR);
#endif

  cur_n = htonl (iter->cur_ipv4_t.ip_int);
  if (iter->type == IPV4_TYPE_NET)
    upper_n = htonl (iter->broad_addr_t.ip_int);
  else
    upper_n = htonl (iter->upper_t.ip_int);

  if (cur_n <= upper_n)
    {
      if (out)
        *out = iter->cur_ipv4_t.ip;

      IPV4_INC (iter->cur_ipv4_t.ip_int);
      return (ITER_CONTINUE);
    }
  else
    {
      if (iter->list->next)
        {
          net_iplistv4_iter_init (iter, iter->list->next);
          return (net_iplistv4_iter_next (iter, out));
        }
    }

  return (ITER_FINISH);
}

void
net_portlist_print (struct portlist_t *list)
{
  while (list != NULL)
    {
      if (list->lower == list->upper)
        fprintf (stdout, "    %d\n", list->lower);
      else
        fprintf (stdout, "    %d-%d\n", list->lower, list->upper);

      list = list->next;
    }
}

static struct portlist_t *
net_portlist_add (struct portlist_t *head, uint32_t lower, uint32_t upper)
{
  struct portlist_t *ptr;

  if (lower > upper)
    return (NULL);

  ptr = malloc (sizeof (struct portlist_t));
  if (ptr == NULL)
    fatal ("%s: net_portlist_add: out of memory allocating %d-bytes\n",
           arg_progname, sizeof (struct portlist_t));

  ptr->next = head;
  ptr->lower = lower;
  ptr->upper = upper;

  return (ptr);
}

void
net_portlist_free (struct portlist_t *head)
{
  while (head != NULL)
    {
      struct portlist_t *ptr;

      ptr = head->next;
      free (head);
      head = ptr;
    }
}

unsigned long long
net_portlist_sum (struct portlist_t *head)
{
  unsigned long long cur_sum;

  if (head == NULL)
    return (0);

  cur_sum = 0;
  while (head != NULL)
    {
      cur_sum += head->upper - head->lower + 1;
      head = head->next;
    }

  return (cur_sum);
}

static int
net_parse_portlist_item (char *port, uint16_t *lower, uint16_t *upper)
{
  char *lptr, *uptr, *tmp;

  lptr = port;
  if ((uptr = strchr (lptr, '-')))
    {
      *uptr++ = '\0';       /* remove '-' */
      *lower = strtol (lptr, &tmp, 10);
      if (lptr[0] == '+' || lptr[0] == '-' || *tmp != '\0')
        return (SYN_ERR);

      *upper = strtol (uptr, &tmp, 10);
      if (uptr[0] == '+' || uptr[0] == '-' || *tmp != '\0')
        return (SYN_ERR);

      if (*lower == 0 || *upper < *lower)
        return (SYN_ERR);
    }
  else
    {
      *lower = strtol (lptr, &tmp, 10);
      if (lptr[0] == '+' || lptr[0] == '-' || *tmp != '\0')
        return (SYN_ERR);

      *upper = *lower;
    }

  return (SYN_OK);
}

struct portlist_t *
net_parse_portlist (char *arg)
{
  struct portlist_t *head;
  char *ptr;
  char port[MAX_PORTLIST];

  /* empty the list */
  head = NULL;

  ptr = strtok (arg, ",");
  while (ptr != NULL)
    {
      struct portlist_t *cur_head;
      uint16_t lower, upper;
      int len;

      len = strlen (ptr);
      if (len < 0 || len > sizeof port - 1)
        goto cleanup;

      strncpy (port, ptr, len);
      port[len] = '\0';

      if (net_parse_portlist_item (port, &lower, &upper) == SYN_ERR)
        goto cleanup;

      if ((cur_head = net_portlist_add (head, lower, upper)) == NULL)
        goto cleanup;
      else
        head = cur_head;

      ptr = strtok (NULL, ",");
    }

  return (head);

cleanup:
  net_portlist_free (head);
  return (NULL);
}

struct portlist_t *
net_parse_portlist_file (char *filen, FILE *filen_fp)
{
  struct portlist_t *head;
  char port[MAX_PORTLIST];

  /* empty the list */
  head = NULL;

  while (fgets (port, sizeof port, filen_fp))
    {
      struct portlist_t *cur_head;
      char *ptr;
      uint16_t lower, upper;

      /* chomp the newline */
      ptr = port + strlen (port) - 1;
      while (ptr >= port && (*ptr == '\r' || *ptr == '\n'))
        {
          *ptr = '\0';
          if (ptr > port)
            ptr--;
        }

      /* blank line */
      if (ptr == port)
        continue;

      if (net_parse_portlist_item (port, &lower, &upper) == SYN_ERR)
        goto cleanup;

      if ((cur_head = net_portlist_add (head, lower, upper)) == NULL)
        goto cleanup;
      else
        head = cur_head;
    }

  return (head);

cleanup:
  net_portlist_free (head);
  return (NULL);
}

struct portlist_iter_t *
net_portlist_iter_init (struct portlist_iter_t *iter, struct portlist_t *list)
{
#ifdef DEBUG
  if (iter == NULL || list == NULL)
    return (NULL);
#endif

  iter->list = list;
  iter->cur_port = list->lower;

  return (iter);
}

unsigned long long
net_portlist_iter_sum (struct portlist_iter_t *iter, struct portlist_t *list)
{
  unsigned long long cur_sum;
  struct portlist_t *head;

#ifdef DEBUG
  if (iter == NULL || list == NULL)
    return (NULL);
#endif

  cur_sum = 0;
  head = list;

  while (head != NULL && head != iter->list)
    {
      cur_sum += head->upper - head->lower + 1;
      head = head->next;
    }

  if (head == iter->list)
    {
      cur_sum += iter->cur_port - head->lower + 1;
    }

  return (cur_sum);
}

enum iter_t
net_portlist_iter_next (struct portlist_iter_t *iter, uint16_t *out)
{
#ifdef DEBUG
  if (iter == NULL)
    return (ITER_ERROR);
#endif

  /* assert (iter->cur_port >= iter->list->lower); */
  if (iter->cur_port <= iter->list->upper)
    {
      if (out)
        *out = iter->cur_port;

      iter->cur_port++;
      return (ITER_CONTINUE);
    }
  else
    {
      if (iter->list->next)
        {
          net_portlist_iter_init (iter, iter->list->next);
          return (net_portlist_iter_next (iter, out));
        }
    }

  return (ITER_FINISH);
}

int
net_ipv4_parse_flags (char *flags_str, uint8_t *out)
{
  static struct flags_t
  {
    char *str;
    uint8_t val;
  } flags[] =
  { {"CWR", TH_CWR}, {"ECE", TH_ECE},
    {"URG", TH_URG}, {"ACK", TH_ACK},
    {"PSH", TH_PUSH}, {"RST", TH_RST},
    {"SYN", TH_SYN}, {"FIN", TH_FIN} };
  uint8_t tcp_flags;
  char *ptr;

  tcp_flags = 0;
  ptr = strtok (flags_str, ",");
  while (ptr != NULL)
    {
      int i, ok;

      ok = SYN_ERR;
      for (i = 0; i < sizeof flags / sizeof (struct flags_t); i++)
        if (strcmp (ptr, flags[i].str) == 0)
          {
            if ((tcp_flags & flags[i].val))
              {
                warning ("%s: duplicating flags makes you an idiot!@$!\n",
                         arg_progname);
                return (SYN_ERR);
              }

            tcp_flags |= flags[i].val;
            ok = SYN_OK;
            break;
          }

      if (ok != SYN_OK)
        warning ("%s: unrecognised flag \"%s\"\n", arg_progname, ptr);

      ptr = strtok (NULL, ",");
    }

  if (out)
    *out = tcp_flags;

  return (SYN_OK);
}
