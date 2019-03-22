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

#ifndef _SYNSCAN_H
#define _SYNSCAN_H

#define SYNSCAN_URL       "http://www.digit-labs.org/files/tools/synscan/"

/* return flags          */

#define SYN_ERR           -1
#define SYN_OK            0

/* default option values */

#ifndef HOST_DEFIFC
#define SYNSCAN_DEFIFC    "eth0"
#else
#define SYNSCAN_DEFIFC    HOST_DEFIFC
#endif
#define SYNSCAN_DEFPORTS  "1-65535"

#define SYNSCAN_DEFITER   ITER_IPLIST
#define SYNSCAN_DEFBURST  100000
#define SYNSCAN_DEFDELAY  10
#define SYNSCAN_DEFFLAGS  TH_SYN

#define SYNSCAN_MINPKTS   32

/* value flags           */

#define ITER_IPLIST       0
#define ITER_PORTLIST     1

#define IPLIST_BLOCK      0
#define IPLIST_FILE       1

#define PORTLIST_BLOCK    0
#define PORTLIST_FILE     1

#define MAX_BUFSIZE       512
#define MAX_ARGSIZE       MAX_BUFSIZE

extern char *arg_progname;

#endif
