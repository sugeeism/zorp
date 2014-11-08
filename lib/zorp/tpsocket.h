/***************************************************************************
 *
 * Copyright (c) 2000, 2001, 2002 BalaBit IT Ltd, Budapest, Hungary
 * All rights reserved.
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#ifndef ZORP_TPROXY_H_INCLUDED
#define ZORP_TPROXY_H_INCLUDED

#include <zorp/socket.h>

#define Z_TP_LISTEN_SOCKET_MARK 0x40000000

gboolean z_tp_socket_init(void);

#endif
