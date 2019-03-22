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

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <time.h>
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

/* statistics variables */
static time_t start_t;
static unsigned long long num_port = 0;
static unsigned long long num_ip = 0;
static unsigned long long total_scan = 0;

/* static variables */
#ifdef HAVE_GETOPT_LONG
static const struct option syn_options[] = {
  {"block", required_argument, 0, 'b'},     /* IP block */
  {"file", required_argument, 0, 'f'},      /* IP file */
  {"port", required_argument, 0, 'p'},      /* port block */
  {"interface", required_argument, 0, 'I'}, /* interface */
  {"burst", required_argument, 0, 'B'},     /* packet burst length */
  {"time", required_argument, 0, 'T'},      /* time between bursts */
  /*{"rand-time", no_argument, 0, 256}, */  /* time variance */

  {"flags", required_argument, 0, 'F'},     /* IP flags */
  /*{"rand-flags", no_argument, 0, 1024}, *//* randomise IP flags */
  /*{"src-port", required_argument, 0, 2048}, *//* src port */
  /*{"rand-src-port", no_argument, 0, 4096}, *//* randomise src port */

  {"version", no_argument, 0, 'V'},         /* version */
  {"verbose", no_argument, 0, 'v'},         /* verbose output */
  {"help", no_argument, 0, 'h'},            /* print usage */
  {NULL, 0, 0, 0}
};
#endif

static uint32_t signal_quit = 0;
static uint32_t src_ip;

/* static argument variables */
static int arg_iplist;
static char arg_ipliststr[MAX_ARGSIZE*16];
static char arg_portliststr[MAX_ARGSIZE*16];
static int arg_iterfirst;
static int arg_burst;
static int arg_delay;
static uint8_t arg_flags;
static int arg_verbose;

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
           "-b --block\tspecify network blocks to scan\n"
           "-f --file\tspecify network block file to scan\n"
           "-p --port\tspecify port blocks to scan [%s]\n"
           "-P --portlist\titerate over ports first\n"
           "\t\t\tdefault: iterate over IP's first\n"
           "-I --interface\tspecify network interface [%s]\n"
           "-B --burst\tspecify packet burst length [%d]\n"
           "-T --time\tspecify packet send delay between bursts (usec, nX msec)\n"
           "\t\t\tdefault: %d packets are sent, with delay %d usec\n"
           "-F --flags\tspecify IP flags\n"
           "-V --version\tprint version information\n"
           "-v --verbose\tverbose output\n"
           "-h --help\tprint this message\n"
#else
           "-b\t\tspecify network blocks to scan\n"
           "-f\t\tspecify network block file to scan\n"
           "-p\t\tspecify port blocks to scan [%s]\n"
           "-P\t\titerate over ports first\n"
           "\t\tdefault: iterate over IP's first\n"
           "-I\t\tspecify network interface [%s]\n"
           "-B\t\tspecify packet burst length [%d]\n"
           "-T --time\tspecify packet send delay between bursts (usec, nX msec)\n"
           "\t\tdefault: %d packets are sent, with delay %d usec\n"
           "-F\t\tspecify IP flags\n"
           "-V\t\tprint version information\n"
           "-v\t\tverbose output\n"
           "-h\t\tprint this message\n"
#endif
           , SYNSCAN_DEFPORTS, SYNSCAN_DEFIFC, SYNSCAN_DEFBURST,
           SYNSCAN_DEFBURST, SYNSCAN_DEFDELAY);
}

static void
syn_hostportscan (struct net_pkt_t *pkt, uint32_t cur_ip, uint16_t cur_port)
{
  static struct stats_t
  {
    time_t last_t;
    unsigned long long done;
  } stats = { 0, 0};
  static int cur_burst = 0, cur_timeburst = 0;
  time_t tmp_t;

  cur_burst++;
  if (cur_burst >= arg_burst)
    {
      cur_burst = 0;
      usleep (arg_delay);
    }

  net_ipv4_send (pkt, src_ip, cur_ip, cur_port, cur_port);
  stats.done++;

  cur_timeburst++;
  if (cur_timeburst >= SYNSCAN_MINPKTS)
    {
      cur_timeburst = 0;

      if (time (&tmp_t) > stats.last_t)
        {
          double cur_percent;
          char *cur_ip_str;

          stats.last_t = tmp_t;
          cur_ip_str = nlookup (cur_ip);
          cur_percent = (((double) stats.done) / total_scan) * 100;
          fprintf (stdout,
                   "| %15s | %5d | %4d | %6llu | %3.0f | %15llu | %15llu |\r",
                   cur_ip_str, cur_port, (int) (stats.last_t - start_t),
                   stats.done / (stats.last_t >
                                 start_t ? stats.last_t -
                                 start_t : stats.done), cur_percent,
                   stats.done, total_scan - stats.done);
          fflush (stdout);
        }
    }
}

static void
parse_args (int argc, char **argv)
{
  extern char *optarg;
  char *opt_tmp;
  int ch, opt_len;

  if (argc <= 1)
    {
      print_usage (argv);
      exit (EXIT_SUCCESS);
    }

  /* initialise argument globals */
  arg_progname = argv[0];

  arg_iplist = -1;
  memset (arg_ipliststr, 0, sizeof arg_ipliststr);

  memset (arg_portliststr, 0, sizeof arg_portliststr);
  snprintf (arg_portliststr, sizeof arg_portliststr, SYNSCAN_DEFPORTS);
  memset (net_interface, 0, sizeof net_interface);
  snprintf (net_interface, sizeof net_interface, SYNSCAN_DEFIFC);

  arg_iterfirst = SYNSCAN_DEFITER;
  arg_burst = SYNSCAN_DEFBURST;
  arg_delay = SYNSCAN_DEFDELAY;
  arg_flags = SYNSCAN_DEFFLAGS;
  arg_verbose = 0;

#ifndef HAVE_GETOPT_LONG
  while ((ch = getopt (argc, argv, "Pb:f:p:I:B:T:F:Vvh")) != -1)
#else
  while ((ch = getopt_long (argc, argv, "Pb:f:p:I:B:T:F:Vvh", syn_options,
                            NULL)) != -1)
#endif
    {
      switch (ch)
        {
        case 'b':
        case 'f':
          opt_len = strlen (optarg);
          if (opt_len > sizeof arg_ipliststr - 1)
            {
              warning ("%s: IP block%s to long (>%d-bytes)\n",
                       arg_progname, (ch == 'b' ? ""
                                      : " file name"), sizeof arg_ipliststr);
              goto failed;
            }

          arg_iplist = (ch == 'b' ? IPLIST_BLOCK : IPLIST_FILE);
          strncpy (arg_ipliststr, optarg, sizeof arg_ipliststr - 1);
          arg_ipliststr[sizeof arg_ipliststr - 1] = '\0';
          break;

        case 'p':
          opt_len = strlen (optarg);
          if (opt_len > sizeof arg_portliststr - 1)
            {
              warning ("%s: port block to long (>%d-bytes)\n",
                       arg_progname, sizeof arg_portliststr);
              goto failed;
            }

          strncpy (arg_portliststr, optarg, sizeof arg_portliststr - 1);
          arg_portliststr[sizeof arg_portliststr - 1] = '\0';
          break;

        case 'P':
          arg_iterfirst = ITER_PORTLIST;
          break;

        case 'I':
          strncpy (net_interface, optarg, sizeof net_interface - 1);
          net_interface[sizeof net_interface - 1] = '\0';
          break;

        case 'B':
          arg_burst = strtol (optarg, &opt_tmp, 10);
          if (optarg[0] == '+' || optarg[0] == '-' || *opt_tmp != '\0')
            {
              warning ("%s: invalid burst length\n", arg_progname);
              goto failed;
            }
          break;

        case 'T':
          {
            int is_msec;

            is_msec = 0;
            opt_len = strlen (optarg);

            if (optarg[opt_len - 1] == 'X')
              is_msec = 1, optarg[opt_len - 1] = '\0';

            arg_delay = strtol (optarg, &opt_tmp, 10);
            if (optarg[0] == '+' || optarg[0] == '-' || *opt_tmp != '\0')
              {
                warning ("%s: invalid delay time\n", arg_progname);
                goto failed;
              }

            if (is_msec)
              arg_delay *= 1000;
          }
          break;

        case 'F':
          if (net_ipv4_parse_flags (optarg, &arg_flags) != SYN_OK)
            {
              warning ("%s: failed parsing TCP flags\n", arg_progname);
              goto failed;
            }
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

  if (arg_iplist == -1)
    {
      warning ("%s: no hosts to scan!\n", arg_progname);
      goto failed;
    }

  return;

failed:
  /* at least one argument is incorrect.. */
  fatal ("Try `%s -h' for more information\n", arg_progname);
}

static void
synscan_handle_signal (int signum)
{
  static int count = 0;

  /* set the quit flag */
  if (count++ == 1)
    signal_quit = 1;
}

int
main (int argc, char **argv)
{
  struct iplistv4_t *iplist;
  struct portlist_t *portlist;
  struct iplistv4_iter_t iplist_iter;
  struct portlist_iter_t portlist_iter;
  struct net_pkt_t net_pkt;
  time_t total_t;

  /* print the header and parse the arguments */
  print_header ();
  parse_args (argc, argv);

  signal (SIGHUP, synscan_handle_signal);
  signal (SIGINT, synscan_handle_signal);

  /* check for root privs */
  if (getuid () && geteuid ())
    fatal ("%s: getuid(): UID or EUID of 0 required\n", arg_progname);

  /* parse the ip lists */
  iplist = NULL;
  if (arg_iplist == IPLIST_BLOCK)
    iplist = net_parse_iplistv4 (arg_ipliststr);
  else
    {
      if (arg_iplist == IPLIST_FILE)
        {
          char *filen;
          FILE *filen_fp;

          filen = arg_ipliststr;
          if ((filen_fp = fopen (filen, "r")) == NULL)
            fatal ("%s: failed opening ip list file '%s'\n", arg_progname,
                   filen);

          iplist = net_parse_iplistv4_file (filen, filen_fp);

          if (fclose (filen_fp) < 0)
            fatal ("%s: failed closing ip list file '%s'\n", arg_progname,
                   filen);
        }
      else
        {
          fatal ("%s: ip list is not a block nor file! (impossible)\n",
                 arg_progname);
        }
    }

  if (iplist == NULL)
    fatal ("%s: failed parsing ip %s\n", arg_progname,
           (arg_iplist == IPLIST_BLOCK ? "block" : "file"));

  /* parse the port lists */
  portlist = net_parse_portlist (arg_portliststr);
  if (portlist == NULL)
    fatal ("%s: failed parsing port list\n", arg_progname);

  /* get our interfaces IP */
  if (net_get_localip (net_interface, &src_ip) == SYN_ERR)
    fatal ("%s: no ip address found for device %s (non-assigned, or interface down)\n",
           arg_progname, net_interface);

  /* calculate the total number of IPs/ports */
  num_ip = net_iplistv4_sum (iplist);
  num_port = net_portlist_sum (portlist);
  total_scan = num_ip * num_port;

  start_t = time (NULL);

  {
    sock_t rsock;

    /* initialise a raw socket */
    rsock = net_sock_init ();

    /* initialise our packet */
    net_ipv4_pkt_init (&net_pkt, rsock, arg_flags);

    fprintf (stdout, "Scanning networks:\n");
    net_iplistv4_print (iplist);
    fprintf (stdout, "on ports:\n");
    net_portlist_print (portlist);
    fprintf (stdout, "from IP: %s\n\n", nlookup (src_ip));

    fprintf (stdout,
             "-------------------------------------------------------------------------------------\n"
             "| IP              | PORT  | TIME | SPEED  |  %%  | DONE            | REMAINING       |\n");

    if (arg_iterfirst == ITER_IPLIST)
      {
        uint16_t cur_port;

        net_portlist_iter_init (&portlist_iter, portlist);

        while (net_portlist_iter_next (&portlist_iter, &cur_port) == ITER_CONTINUE)
          {
            struct in_addr cur_ip;

            if (signal_quit)
              break;
            net_iplistv4_iter_init (&iplist_iter, iplist);

            while (net_iplistv4_iter_next (&iplist_iter, &cur_ip) == ITER_CONTINUE)
              {
#ifdef DEBUG
                printf ("%s:%d\n", nlookup (cur_ip.s_addr), cur_port);
#endif
                syn_hostportscan (&net_pkt, cur_ip.s_addr, cur_port);
              }
          }
      }
    else
      {
        struct in_addr cur_ip;

        net_iplistv4_iter_init (&iplist_iter, iplist);

        while (net_iplistv4_iter_next (&iplist_iter, &cur_ip) == ITER_CONTINUE)
          {
            uint16_t cur_port;

            if (signal_quit)
              break;
            net_portlist_iter_init (&portlist_iter, portlist);

            while (net_portlist_iter_next (&portlist_iter, &cur_port) ==
                   ITER_CONTINUE)
              {
#ifdef DEBUG
                printf ("%s:%d\n", nlookup (cur_ip.s_addr), cur_port);
#endif
                syn_hostportscan (&net_pkt, cur_ip.s_addr, cur_port);
              }
          }
      }

    fprintf (stdout,
             "\n-------------------------------------------------------------------------------------\n");
  }

  total_t = time (NULL) - start_t;
  if (total_t > 0)
    fprintf (stdout,
             "%llu IPs and %llu ports scanned in %d seconds, avg %llu p/sec%s\n",
             signal_quit && arg_iterfirst != ITER_IPLIST ? net_iplistv4_iter_sum (&iplist_iter, iplist)
                                                         : num_ip,
             signal_quit && arg_iterfirst != ITER_PORTLIST ? net_portlist_iter_sum (&portlist_iter, portlist)
                                                           : num_port,
             (int) total_t,
             signal_quit ? (arg_iterfirst != ITER_IPLIST ? (num_port * net_iplistv4_iter_sum (&iplist_iter, iplist)) / total_t
                                                         : (num_ip * net_portlist_iter_sum (&portlist_iter, portlist)) / total_t)
                         : total_scan / total_t,
             signal_quit ? " [early termination]" : "");
  else
    fprintf (stdout,
             "%llu IPs and %llu ports scanned in <1 second, avg %llu p/sec%s\n",
             signal_quit && arg_iterfirst != ITER_IPLIST ? net_iplistv4_iter_sum (&iplist_iter, iplist)
                                                         : num_ip,
             signal_quit && arg_iterfirst != ITER_PORTLIST ? net_portlist_iter_sum (&portlist_iter, portlist)
                                                           : num_port,
             total_scan,
             signal_quit ? " [early termination]" : "");

  net_ipv4_pkt_free (&net_pkt);
  net_iplistv4_free (iplist);
  net_portlist_free (portlist);

  return (EXIT_SUCCESS);
}
