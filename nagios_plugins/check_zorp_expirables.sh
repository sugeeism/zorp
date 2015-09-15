#!/bin/bash

############################################################################
##
## Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
##
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
##
############################################################################

#Nagios plugin for BalaBit licenses and certificates ==

CHECKER=/etc/cron.daily/expiration_check.py
CHECKER_PARAM="-n" #Do not send mail for nagios checks

usage() {
    cat << EOF
This Nagios plugin is a wrapper around the expiration_check.py found in
the zms-transfer-agent-dynamic package. It can be configured through its
configuration file found in /etc/zmsagent/expiration.conf.
EOF
}

check() {
    $CHECKER $CHECKER_PARAM
    RET=$?
    case "$RET" in
        5)
            echo "Critical: certificates or licenses have been already expired"
            exit 2
        ;;
        4)
            echo "Warning: certificates or licenses are about to expire soon"
            exit 1
        ;;
        3)
            echo "Warning: licenses have their limits reached"
            exit 1
        ;;
        0)
            echo "OK: Certificates and licenses are OK"
            exit 0
        ;;
        *)
            echo "Unkown: error checking certificates and licenses"
            exit 3
    esac
}

if [ "$1" == "-h" -o "$1" == "--help" ]; then
    usage
    exit 0
fi

if [ -x "$CHECKER" ]; then
    check
else
    echo "Unkown: $CHECKER not found, please install the zms-transfer-agent-dynamic package"
    exit 3
fi
