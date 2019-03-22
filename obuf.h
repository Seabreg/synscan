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

#ifndef _OBUF_H
#define _OBUF_H

#define OBUF_PADDING  32
#define DIV_LEN(a, b) ((a)+(b)+((b)-((a)%(b))))
#define DIV_PAD(a, b) ((a)+((a)%(b)))

struct obuf_t {
  int len;

  void *base;
  void *buf;
};

struct obuf_t *
obuf_allocate (struct obuf_t *, int);

void
obuf_free (struct obuf_t *);

#endif
