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

#include <zorp/pysockaddr.h>
#include <zorp/log.h>

#include <netdb.h>
#include <arpa/inet.h>

/**
 * z_policy_sockaddr_inet_new_instance:
 * @s not used
 * @args Python args: ip, port
 *
 * SockAddr.SockAddrInet(ip, port), creates a new ZSockAddrInet.
 *
 * Returns:
 * The new instance
 */
static PyObject *
z_policy_sockaddr_inet_new_instance(PyObject *s G_GNUC_UNUSED, PyObject *args)
{
  ZSockAddr *sa;
  PyObject *res;
  gchar *ip;
  gint port;
  guint32 ip_addr;

  if (PyArg_Parse(args, "(si)", &ip, &port))
    {
      sa = z_sockaddr_inet_new(ip, port);
      if (!sa)
        {
          PyErr_SetString(PyExc_ValueError, "Invalid IP address");
          return NULL;
        }
    }
  else
    {
      PyErr_Clear();
      if (PyArg_Parse(args, "(ii)", &ip_addr, &port))
        {
          struct sockaddr_in socket;

          memset(&socket, 0, sizeof(socket));

          socket.sin_family = AF_INET;
          socket.sin_addr.s_addr = htonl(ip_addr);
          socket.sin_port = htons(port);

          sa = z_sockaddr_inet_new2(&socket);
          if (!sa)
            {
              PyErr_SetString(PyExc_ValueError, "Invalid IP address");
              return NULL;
            }
        }
      else
        {
          PyErr_SetString(PyExc_ValueError, "Invalid parameter");
          return NULL;
        }
    }

  res = z_policy_sockaddr_new(sa);
  z_sockaddr_unref(sa);

  return res;
}

/**
 * z_policy_sockaddr_inet_new_hostname:
 * @s not used
 * @args Python args: ip, port
 *
 * SockAddr.SockAddrInetHostname(hostname port), creates a new ZSockAddrInet.
 *
 * Returns:
 * The new instance
 */
static PyObject *
z_policy_sockaddr_inet_new_hostname(PyObject *s G_GNUC_UNUSED, PyObject *args)
{
  ZSockAddr *sa;
  PyObject *res;
  gchar *hostname;
  gint port;

  if (PyArg_Parse(args, "(si)", &hostname, &port))
    {
      sa = z_sockaddr_inet_new_hostname(hostname, port);
      if (!sa)
        {
          PyErr_SetString(PyExc_ValueError, "Invalid hostname");
          return NULL;
        }
    }
  else
    {
      PyErr_SetString(PyExc_ValueError, "Invalid parameter");
      return NULL;
    }

  res = z_policy_sockaddr_new(sa);
  z_sockaddr_unref(sa);

  return res;
}

/**
 * z_policy_sockaddr_inet_new_instance:
 * @s not used
 * @args Python args: ip, port_min, port_max
 *
 * Implementation of SockAddrInetRange(ip, port_min, port_max), creates a new
 * ZSockAddrInetRange.
 *
 * Returns:
 * The new instance
 */
static PyObject *
z_policy_sockaddr_inet_range_new_instance(PyObject *s G_GNUC_UNUSED, PyObject *args)
{
  PyObject *res;
  ZSockAddr *sa;
  gchar *ip;
  gint min_port, max_port;

  if (!PyArg_Parse(args, "(sii)", &ip, &min_port, &max_port))
    return NULL;

  sa = z_sockaddr_inet_range_new(ip, min_port, max_port);

  if (!sa)
    {
      PyErr_SetString(PyExc_ValueError, "Invalid IP address");
      return NULL;
    }
  res = z_policy_sockaddr_new(sa);
  z_sockaddr_unref(sa);
  return res;
}

/**
 * z_policy_sockaddr_inet6_new_instance:
 * @s not used
 * @args Python args: ip, port
 *
 * SockAddr.SockAddrInet6(ip, port), creates a new ZSockAddrInet6.
 *
 * Returns:
 * The new instance
 */
static PyObject *
z_policy_sockaddr_inet6_new_instance(PyObject *s G_GNUC_UNUSED, PyObject *args)
{
  PyObject *res;
  ZSockAddr *sa;
  gchar *ip;
  gint port;

  if (!PyArg_Parse(args, "(si)", &ip, &port))
    return NULL;

  sa = z_sockaddr_inet6_new(ip, port);

  if (!sa)
    {
      PyErr_SetString(PyExc_ValueError, "Invalid IP address");
      return NULL;
    }
  res = z_policy_sockaddr_new(sa);
  z_sockaddr_unref(sa);
  return res;
}

/**
 * z_policy_sockaddr_unix_new_instance:
 * @s not used
 * @args Python args: path
 *
 * SockAddr.SockAddrUnix(path), creates a new ZSockAddrUnix.
 *
 * Returns:
 * The new instance
 */
static PyObject *
z_policy_sockaddr_unix_new_instance(PyObject *s G_GNUC_UNUSED, PyObject *args)
{
  ZSockAddr *sa;
  PyObject *res;
  gchar *path;

  if (!PyArg_Parse(args, "(s)", &path))
    return NULL;

  sa = z_sockaddr_unix_new(path);
  res = z_policy_sockaddr_new(sa);
  z_sockaddr_unref(sa);
  return res;
}

PyMethodDef z_policy_sockaddr_funcs[] =
{
  { "SockAddrInet",  z_policy_sockaddr_inet_new_instance, METH_VARARGS, NULL },
  { "SockAddrInetRange",  z_policy_sockaddr_inet_range_new_instance, METH_VARARGS, NULL },
  { "SockAddrInetHostname", z_policy_sockaddr_inet_new_hostname, METH_VARARGS, NULL },
  { "SockAddrInet6", z_policy_sockaddr_inet6_new_instance, METH_VARARGS, NULL },
  { "SockAddrUnix",  z_policy_sockaddr_unix_new_instance, METH_VARARGS, NULL },
  { NULL,            NULL, 0, NULL }   /* sentinel*/
};

/**
 * z_policy_sockaddr_format:
 * @self this
 *
 * Produce a human-readable dump of a ZSockAddr.
 *
 * Returns:
 * Python string containing the dump
 */
static ZPolicyObj *
z_policy_sockaddr_format(gpointer user_data, ZPolicyObj *args, ZPolicyObj *kw G_GNUC_UNUSED)
{
  ZSockAddr *sa = (ZSockAddr *) user_data;
  char buf[MAX_SOCKADDR_STRING];

  if (!z_policy_var_parse(args, "()"))
    return NULL;

  return PyString_FromString(z_sockaddr_format(sa, buf, sizeof(buf)));
}

/**
 * z_policy_sockaddr_clone:
 * @self this
 * @args Python args: wild_flags
 *
 * SockAddr.clone, Copy-constructor of SockAddr.
 *
 * Returns:
 * New instance
 */
static ZPolicyObj *
z_policy_sockaddr_clone(gpointer user_data, ZPolicyObj *args, ZPolicyObj *kw G_GNUC_UNUSED)
{
  PyObject *res;
  gint wild;
  ZSockAddr *sa = (ZSockAddr *) user_data, *a;

  if (!z_policy_var_parse(args, "(i)", &wild))
    return NULL;

  a = z_sockaddr_clone(sa, wild);
  res = z_policy_sockaddr_new(a);
  z_sockaddr_unref(a);
  return res;
}

/**
 * z_policy_sockaddr_equal:
 * @self this
 * @args Python args: wild_flags
 *
 * SockAddr.clone, Copy-constructor of SockAddr.
 *
 * Returns:
 * New instance
 */
static ZPolicyObj *
z_policy_sockaddr_equal(gpointer user_data, ZPolicyObj *args, ZPolicyObj *kw G_GNUC_UNUSED)
{
  PyObject *other_obj, *res;
  ZSockAddr *this_sa = (ZSockAddr *) user_data, *other_sa;

  if (!z_policy_var_parse(args, "(O)", &other_obj))
    return NULL;

  if (!z_policy_sockaddr_check(other_obj))
    {
      PyErr_SetString(PyExc_ValueError, "Argument must be a SockAddr instance");
      return NULL;
    }
  other_sa = z_policy_sockaddr_get_sa(other_obj);
  res = PyInt_FromLong(z_sockaddr_equal(this_sa, other_sa));
  z_sockaddr_unref(other_sa);

  return res;
}

ZSockAddr *
z_policy_sockaddr_get_sa(ZPolicyObj *s)
{
  ZSockAddr *sa;

  if (!z_policy_sockaddr_check(s))
    return NULL;
  sa = (ZSockAddr *) z_policy_dict_get_app_data(z_policy_struct_get_dict(s));
  return z_sockaddr_ref(sa);
}

static ZPolicyObj *
z_policy_sockaddr_str(ZPolicyObj *s)
{
  ZSockAddr *sa = z_policy_sockaddr_get_sa(s);
  ZPolicyObj *res;
  char buf[MAX_SOCKADDR_STRING];

  res = PyString_FromString(z_sockaddr_format(sa, buf, sizeof(buf)));
  z_sockaddr_unref(sa);
  return res;
}

/**
 * z_policy_sockaddr_pack:
 * @self this
 *
 * SockAddr.pack, get a packed string representation of the address
 *
 * Returns:
 * A string representation of the address in network byte order packed format.
 * Returns None if the address family is not INET or INET6.
 */
static ZPolicyObj *
z_policy_sockaddr_pack(gpointer user_data, ZPolicyObj *args G_GNUC_UNUSED, ZPolicyObj *kw G_GNUC_UNUSED)
{
  ZSockAddr *sa = (ZSockAddr *) user_data;

  switch (sa->sa.sa_family)
  {
    case AF_INET:
      {
        struct sockaddr_in *sa_in = (struct sockaddr_in *) &sa->sa;
        return PyString_FromStringAndSize((gchar*)&sa_in->sin_addr, 4);
        break;
      }
    case AF_INET6:
      {
        struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *) &sa->sa;
        return PyString_FromStringAndSize((gchar*)&sa_in6->sin6_addr, 16);
        break;
      }
    default:
      return z_policy_none_ref();
  }
}
/**
 * z_policy_sockaddr_new:
 * @sa ZSockAddr address
 *
 * Constructor of ZPolicySockAddr, creates new instance by ZSockAddr.
 *
 * Returns:
 * The new instance
 */
ZPolicyObj *
z_policy_sockaddr_new(ZSockAddr *sa)
{
  ZPolicyDict *dict;
  ZPolicyObj *res;
  gint struct_type;

  dict = z_policy_dict_new();
  z_policy_dict_register(dict, Z_VT_INT16, "family", Z_VF_READ | Z_VF_LITERAL, sa->sa.sa_family);
  z_policy_dict_register(dict, Z_VT_METHOD, "clone", Z_VF_READ, z_policy_sockaddr_clone, z_sockaddr_ref(sa), z_sockaddr_unref);
  z_policy_dict_register(dict, Z_VT_METHOD, "format", Z_VF_READ, z_policy_sockaddr_format, z_sockaddr_ref(sa), z_sockaddr_unref);
  z_policy_dict_register(dict, Z_VT_METHOD, "equal", Z_VF_READ, z_policy_sockaddr_equal, z_sockaddr_ref(sa), z_sockaddr_unref);

  switch (sa->sa.sa_family)
    {
    case AF_INET:
      {
        struct sockaddr_in *sa_in = (struct sockaddr_in *) &sa->sa;

        /* FIXME: inconsistency, port is reported in host byte order,
         * ip in network byte order */
        z_policy_dict_register(dict, Z_VT_CSTRING, "type", Z_VF_READ | Z_VF_LITERAL, "inet", 0);
        z_policy_dict_register(dict, Z_VT_IP,      "ip",   Z_VF_RW, &sa_in->sin_addr);
        z_policy_dict_register(dict, Z_VT_IP,      "ip_s", Z_VF_RW | Z_VF_IP_STR, &sa_in->sin_addr);
        z_policy_dict_register(dict, Z_VT_INT16,   "port", Z_VF_RW | Z_VF_INT_NET, &sa_in->sin_port);
        z_policy_dict_register(dict, Z_VT_METHOD,  "pack", Z_VF_READ, z_policy_sockaddr_pack, z_sockaddr_ref(sa), z_sockaddr_unref);
        struct_type = Z_PST_SOCKADDR_INET;
        break;
      }
    case AF_INET6:
      {
        struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *) &sa->sa;

        z_policy_dict_register(dict, Z_VT_CSTRING, "type", Z_VF_READ | Z_VF_LITERAL, "inet", 0);
        z_policy_dict_register(dict, Z_VT_IP6,     "ip",   Z_VF_RW, &sa_in6->sin6_addr);
        z_policy_dict_register(dict, Z_VT_IP6,     "ip_s", Z_VF_RW | Z_VF_IP_STR, &sa_in6->sin6_addr);
        z_policy_dict_register(dict, Z_VT_INT16,   "port", Z_VF_RW | Z_VF_INT_NET, &sa_in6->sin6_port);
        z_policy_dict_register(dict, Z_VT_METHOD,  "pack", Z_VF_READ, z_policy_sockaddr_pack, z_sockaddr_ref(sa), z_sockaddr_unref);
        struct_type = Z_PST_SOCKADDR_INET6;
        break;
      }
    case AF_UNIX:
      {
        struct sockaddr_un *sa_un = (struct sockaddr_un *) &sa->sa;

        z_policy_dict_register(dict, Z_VT_CSTRING, "type", Z_VF_READ | Z_VF_LITERAL, "unix", 0);
        z_policy_dict_register(dict, Z_VT_CSTRING, "path", Z_VF_RW, sa_un->sun_path, sizeof(sa_un->sun_path));
        struct_type = Z_PST_SOCKADDR_UNIX;
        break;
      }
    default:
      z_policy_dict_destroy(dict);
      return NULL;
    }
  z_policy_dict_set_app_data(dict, z_sockaddr_ref(sa), (GDestroyNotify) z_sockaddr_unref);
  res = z_policy_struct_new(dict, struct_type);
  z_policy_struct_set_format(res, z_policy_sockaddr_str);

  return res;
}

/**
 * z_policy_sockaddr_init:
 *
 * Module initialisation
 */
void
z_policy_sockaddr_module_init(void)
{
  Py_InitModule("Zorp.SockAddr", z_policy_sockaddr_funcs);
}
