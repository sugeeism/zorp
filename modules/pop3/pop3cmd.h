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

#ifndef ZORP_MODULES_POP3CMD_H_INCLUDED
#define ZORP_MODULES_POP3CMD_H_INCLUDED

guint Pop3ParseNoarg(Pop3Proxy *self);
guint Pop3ParseNum_One(Pop3Proxy *self);
guint Pop3ParseNum_OneOptional(Pop3Proxy *self);
guint Pop3ParseLIST(Pop3Proxy *self);
guint Pop3ParseNum_Two(Pop3Proxy *self);
guint Pop3ParseUSER(Pop3Proxy *self);
guint Pop3ParsePASS(Pop3Proxy *self);
guint Pop3ParseAPOP(Pop3Proxy *self);
guint Pop3ParseAUTH(Pop3Proxy *self);
guint Pop3ParseRETR(Pop3Proxy *self);
guint Pop3AnswerParseUSER(Pop3Proxy *self);
guint Pop3AnswerParsePASS(Pop3Proxy *self);
guint Pop3AnswerParseAPOP(Pop3Proxy *self);
guint Pop3AnswerParseQUIT(Pop3Proxy *self);
guint Pop3AnswerParseAUTH(Pop3Proxy *self);
guint Pop3AnswerParseNum_One(Pop3Proxy *self);
guint Pop3AnswerParseNum_Two(Pop3Proxy *self);

#endif
