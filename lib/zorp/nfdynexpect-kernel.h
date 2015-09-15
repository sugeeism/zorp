/***************************************************************************
 *
 * Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 ***************************************************************************/

#ifndef _IP_CONNTRACK_DYNEXPECT_H
#define _IP_CONNTRACK_DYNEXPECT_H

#include <sys/types.h>

#define SO_DYNEXPECT_MAP 11281
#define SO_DYNEXPECT_EXPECT 11282
#define SO_DYNEXPECT_DESTROY 11283
#define SO_DYNEXPECT_MARK 11284

struct ip_ct_dynexpect_map
{
        u_int32_t mapping_id;
        u_int32_t orig_ip;
        u_int32_t new_ip;
        u_int16_t orig_port;
        u_int16_t n_ports;
        u_int16_t new_port;
        u_int8_t proto;
        u_int8_t _res1;
        u_int32_t n_active;
} __attribute__((packed));

struct ip_ct_dynexpect_expect
{
        u_int32_t mapping_id;
        u_int32_t peer_ip;
        u_int16_t peer_port;
} __attribute__((packed));

struct ip_ct_dynexpect_destroy
{
        u_int32_t mapping_id;
} __attribute__((packed));

struct ip_ct_dynexpect_mark
{
        u_int32_t mapping_id;
        u_int32_t mark;
} __attribute__((packed));

#endif /* _IP_CONNTRACK_DYNEXPECT_H */
