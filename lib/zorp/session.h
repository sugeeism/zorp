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
 *
 ***************************************************************************/

#ifndef ZORP_SESSION_H_INCLUDED
#define ZORP_SESSION_H_INCLUDED

typedef enum _ZSessionLimitVerdict
{
  Z_SLV_NOT_EXCEEDED             = 0,
  Z_SLV_GRACEFULLY_EXCEEDED      = 1,
  Z_SLV_EXCEEDED                 = 2,
} ZSessionLimitVerdict;

gint z_session_get_max(void);
void z_session_set_max(gint max);


#endif /* ZORP_SESSION_H_INCLUDED */
