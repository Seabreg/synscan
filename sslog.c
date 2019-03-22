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

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <fcntl.h>
#include <pcap.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "net.h"
#include "synscan.h"

/* global variables */
char net_interface[MAX_IFNAMELEN];      /* network interface */
char *arg_progname;                     /* program name      */

/* static variables */
#ifdef HAVE_GETOPT_LONG
static const struct option syn_options[] = {
  {"file", required_argument, 0, 'f'},      /* file to output to */
  {"flush", no_argument, 0, 'l'},           /* fflush file */
  {"interface", required_argument, 0, 'I'}, /* interface */
  {"version", no_argument, 0, 'V'},         /* version */
  {"verbose", no_argument, 0, 'v'},         /* verbose output */
  {"help", no_argument, 0, 'h'},            /* print usage */
  {NULL, 0, 0, 0}
};
#endif

static uint32_t src_ip;

/* static argument variables */
static char arg_filename[MAX_ARGSIZE];
static int arg_use_file;
static FILE *arg_file;
static int arg_verbose;
static int arg_fflush;

static void
print_header (void)
{
  fprintf (stdout, PACKAGE_STRING " (" SYNSCAN_URL ")\n"
           "by John Anderson <john [at] ev6.net>,\n"
           "   Neil Kettle <mu-b [at] digit-labs.org>.\n\n");
}

static void
print_usage (char **argv)
{
  fprintf (stdout, "Usage: %s [options]\n\n", argv[0]);
  fprintf (stdout,
#ifdef HAVE_GETOPT_LONG
           "-f --file\tsave output to file\n"
           "-l --flush\tflush the output file upon every result\n"
           "-I --interface\tspecify network interface [%s]\n"
           "-V --version\tprint version information\n"
           "-v --verbose\tverbose output\n"
           "-h --help\tprint this message\n"
#else
           "-f\t\tspecify network block file to scan\n"
           "-l\t\tflush the output file upon every result\n"
           "-I\t\tspecify network interface [%s]\n"
           "-V\t\tprint version information\n"
           "-v\t\tverbose output\n"
           "-h\t\tprint this message\n"
#endif
           , SYNSCAN_DEFIFC);
}

static void
parse_args (int argc, char **argv)
{
  extern char *optarg;
  int ch, opt_len;

  /* initialise argument globals */
  arg_progname = argv[0];

  memset (net_interface, 0, sizeof net_interface);
  snprintf (net_interface, sizeof net_interface, SYNSCAN_DEFIFC);

  arg_use_file = 0;
  arg_verbose = 0;
  arg_fflush = 0;

#ifndef HAVE_GETOPT_LONG
  while ((ch = getopt (argc, argv, "f:l:I:Vvh")) != -1)
#else
  while ((ch = getopt_long (argc, argv, "f:l:I:Vvh", syn_options,
                            NULL)) != -1)
#endif
    {
      switch (ch)
        {
        case 'f':
          opt_len = strlen (optarg);
          if (opt_len > sizeof arg_filename - 1)
            {
              warning ("%s: output filename too long (>%d-bytes)\n",
                       arg_progname, sizeof arg_filename);
              goto failed;
            }

          arg_use_file = 1;
          strncpy (arg_filename, optarg, sizeof arg_filename - 1);
          arg_filename[sizeof arg_filename - 1] = '\0';
          break;

        case 'l':
          arg_fflush = 1;
          break;
        case 'I':
          strncpy (net_interface, optarg, sizeof net_interface - 1);
          net_interface[sizeof net_interface - 1] = '\0';
          break;

        case 'V':
          exit (EXIT_SUCCESS);
          break;
        case 'v':
          arg_verbose++;
          break;
        case 'h':
          print_usage (argv);
        default:
          exit (EXIT_FAILURE);
        }
    }

  return;

failed:
  /* at least one argument is incorrect.. */
  fatal ("Try `%s -h' for more information\n", arg_progname);
}

static void
pcap_alarm_handler (int arg)
{
  warning ("%s: pcap alarm!$%!\n", arg_progname);
}

static int
pcap_initialise (pcap_t **pcap_gbl, int *pcap_pkt_offset)
{
  struct sigaction pcap_sgnl;
  pcap_t *pcap_lcl;
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  int dlink, pcap_offset;

  memset (&pcap_sgnl, 0, sizeof (struct sigaction));
  pcap_sgnl.sa_handler = pcap_alarm_handler;
  pcap_sgnl.sa_flags = 0;
  if (sigaction (SIGALRM, &pcap_sgnl, NULL) < 0)
    fatal ("%s: pcap_initialise: sigaction() failed\n", arg_progname);

  pcap_lcl = pcap_open_live (net_interface,
                             sizeof (struct ip_hdr_t) + sizeof (struct tcp_hdr_t) + 32,
                             0, 1000, pcap_errbuf);
  if (pcap_lcl == NULL)
    fatal ("%s: pcap_open_live (): failed, %s\n", arg_progname, pcap_errbuf);

  dlink = pcap_datalink (pcap_lcl);
  switch (dlink)
    {
    case DLT_EN10MB:
      pcap_offset = 14;
      break;

    case DLT_NULL:
    case DLT_PPP:
      pcap_offset = 4;
      break;

    case DLT_SLIP:
      pcap_offset = 16;
      break;

    case DLT_RAW:
      pcap_offset = 0;
      break;

    case DLT_SLIP_BSDOS:
    case DLT_PPP_BSDOS:
      pcap_offset = 24;
      break;

    case DLT_ATM_RFC1483:
      pcap_offset = 8;
      break;

    case DLT_IEEE802:
      pcap_offset = 22;
      break;

    default:
      warning ("%s: pcap_datalink (): unknown datalink type (%d)",
               arg_progname, dlink);
      return (SYN_ERR);
    }

  if (pcap_gbl)
    *pcap_gbl = pcap_lcl;

  if (pcap_pkt_offset)
    *pcap_pkt_offset = pcap_offset;

  return (SYN_OK);
}

void
sslog_pcap_recv (unsigned char *arg, const struct pcap_pkthdr *pcap_hdr,
                 const unsigned char *pkt)
{
  struct ip_hdr_t *ip_hdr;
  struct tcp_hdr_t *tcp_hdr;
  int pkt_offset;

#ifdef DEBUG
  fprintf (stdout, "sslog_pcap_recv: called, pkt->len: %d, ", pcap_hdr->len);
#endif

  pkt_offset = (int) ((long) arg);
  ip_hdr = (void *) pkt + pkt_offset;
  tcp_hdr = (void *) ip_hdr + sizeof (struct ip_hdr_t);

#ifdef DEBUG
  fprintf (stdout, "ip_v: %d, ip_p: %d\n", ip_hdr->ip_v, ip_hdr->ip_p);
#endif

#ifndef USE_PCAP_FILTER
  if (ip_hdr->ip_v == 4)
    {
      if (ip_hdr->ip_p == IPPROTO_TCP)
        {
          if ((tcp_hdr->tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
            {
              if (ip_hdr->ip_src_t.ip_src_int != src_ip)
                {
                  if (tcp_hdr->tcp_sport == tcp_hdr->tcp_dport)
                    {
                      if (ip_hdr->ip_dst_t.ip_dst_int == src_ip)
                        {
                          fprintf (stdout, "%s:%d\n",
                                   nlookup (ip_hdr->ip_src_t.ip_src_int),
                                   ntohs (tcp_hdr->tcp_sport));

                          if (arg_use_file)
                            {
                              fprintf (arg_file, "%s:%d\n",
                                       nlookup (ip_hdr->ip_src_t.ip_src_int),
                                       ntohs (tcp_hdr->tcp_sport));
                              if (arg_fflush)
                                fflush (arg_file);
                            }

                          fflush (stdout);
                        }
                    }
                }
            }
        }
    }
#else
#ifdef DEBUG
  assert ((tcp_hdr->tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK));
#endif

  if (ip_hdr->ip_dst_t.ip_dst_int != src_ip)
    {
      if (tcp_hdr->tcp_sport == tcp_hdr->tcp_dport)
        {
          if (ip_hdr->ip_src_t.ip_src_int == src_ip)
            {
              fprintf (stdout, "%s:%d\n",
                       nlookup (ip_hdr->ip_dst_t.ip_dst_int),
                       ntohs (tcp_hdr->tcp_sport));

              if (arg_use_file)
                {
                  fprintf (arg_file, "%s:%d\n",
                           nlookup (ip_hdr->ip_dst_t.ip_dst_int),
                           ntohs (tcp_hdr->tcp_sport));
                  if (arg_fflush)
                    fflush (arg_file);
                }

              fflush (stdout);
            }
        }
    }
#endif
}

#ifdef USE_PCAP_FILTER
static void
pcap_filter_install (pcap_t *pcap_gbl)
{
  struct bpf_program filter_p;  
  char filter_exp[] = "(ip proto \\tcp) and " \
                      "((tcp[13] & tcp-syn) = 0) and " \
                      "((tcp[13] & tcp-ack) = 0)";

  /* Compile and apply the filter */
  if (pcap_compile (pcap_gbl, &filter_p, filter_exp, 0, src_ip) == -1)
    fatal ("%s: pcap_compile (): couldn't parse filter %s: %s\n",
           filter_exp, pcap_geterr (pcap_gbl));

  if (pcap_setfilter (pcap_gbl, &filter_p) == -1)
    fatal ("%s: pcap_compile (): couldn't install filter %s: %s\n",
           filter_exp, pcap_geterr (pcap_gbl));
}
#endif

static void
sslog_handle_signal (int signum)
{
  static int count = 0;

  if (count++ == 0)
    warning ("%s: received, again to close...\n",
             signum == SIGHUP ? "SIGHUP" : "SIGINT");
  else
    {
      warning ("%s: received, closing...\n",
               signum == SIGHUP ? "SIGHUP" : "SIGINT");

      if (arg_use_file)
        {
          if (fclose (arg_file) < 0)
            fatal ("%s: failed closing output file '%s'\n", arg_progname,
                   arg_filename);
        }

      exit (EXIT_SUCCESS);
    }
}

int
main (int argc, char **argv)
{
  pcap_t *pcap_gbl;
  int pcap_pkt_offset;

  /* print the header and parse the arguments */
  print_header ();
  parse_args (argc, argv);

  signal (SIGHUP, sslog_handle_signal);
  signal (SIGINT, sslog_handle_signal);

  /* check for root privs */
  if (getuid () && geteuid ())
    fatal ("%s: getuid(): UID or EUID of 0 required\n", arg_progname);

  /* get our interfaces IP */
  if (net_get_localip (net_interface, &src_ip) == SYN_ERR)
    fatal ("%s: no ip address found for device %s (non-assigned, or interface down)\n",
           arg_progname, net_interface);

  fprintf (stdout, "Listening on IP: %s\n", nlookup (src_ip));

  /* open our output file */
  if (arg_use_file)
    {
      char *filen;

      filen = arg_filename;
      if ((arg_file = fopen (filen, "w")) == NULL)
        fatal ("%s: failed opening file '%s' for output\n", arg_progname,
               filen);

      fprintf (stdout, "Writing output to file: %s\n", filen);
    }

  pcap_gbl = NULL;
  pcap_pkt_offset = 0;
  if (pcap_initialise (&pcap_gbl, &pcap_pkt_offset) == SYN_ERR)
    fatal ("%s: pcap_initialise (): failed\n", arg_progname);

#ifdef USE_PCAP_FILTER
  pcap_filter_install (pcap_gbl);
#endif

  fprintf (stdout, "\nWaiting for traffic\n\n");

  pcap_loop (pcap_gbl, -1, (pcap_handler) sslog_pcap_recv, (unsigned char *) ((long) pcap_pkt_offset));

  return (EXIT_SUCCESS);
}
