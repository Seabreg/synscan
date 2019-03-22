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

#include "common.h"
#include "obuf.h"
#include "synscan.h"

struct obuf_t *
obuf_allocate (struct obuf_t *ptr, int len)
{
  int pad_len;

  if (ptr == NULL)
    return (NULL);

  pad_len = DIV_LEN (len, OBUF_PADDING);
  ptr->len = len;
  ptr->base = malloc (pad_len);
  if (ptr->base == NULL)
    fatal ("%s: obuf_allocate: out of memory allocating %d-bytes\n",
           arg_progname, pad_len);

  ptr->buf = (void *) DIV_PAD ((unsigned long) ptr->base, OBUF_PADDING);

  return (ptr);
}

void
obuf_free (struct obuf_t *ptr)
{
  if (ptr == NULL)
    return;

  free (ptr->base);
}
