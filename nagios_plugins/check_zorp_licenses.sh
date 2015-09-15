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

# set -x

### == Nagios plugin for BalaBit licenses ==

VERSION="0.0.14"
VERBOSE="0"
RETURN="0"

CRITICAL="15"
WARNING="30"

OUTTEXT=""
VERBTEXT=""

### ===================

usage() {
echo "
NAME
    $PROGRAM_NAME - Nagios plugin for Balabit licenses.
SYNOPSIS
    $PROGRAM_NAME --warn=<days> --critical=<days>
    $PROGRAM_NAME -w<days> -c<days>
    $PROGRAM_NAME -[hv]
USAGE
    $0 options
    Usage: $PROGRAM_NAME --warn=<days> --critical=<days>
DESCRIPTION
    $PROGRAM_NAME a bash plugin for nagios. You can start with warning and critical parameters. $PROGRAM_NAME search Balabit product licenses, and examine
    the expire date and current date. If a product expire date near to the current date return a warning or a critical status.
EXAMPLES
    $PROGRAM_NAME -w30 -c15
        Set warning level to 30 and critical level 15 day. Search Balabit product licenses, examine and write output to stdout.
    $PROGRAM_NAME -c 30
        Set critical level to 30 day. Warning level the default (15). Search Balabit product licenses, examine and write output to stdout.
    $PROGRAM_NAME -v
        Display verbose output.
    $PROGRAM_NAME -h
        Display this message.
    $PROGRAM_NAME -V
        Display plugin version.
OPTIONS
    -h      Display this message
    -V      Display plugin version
    -c      Set to critical level. Default: 15.
    -w      Warning level in days. Default: 30.
    -v      Verbose output
"
}

### ===================

function vizsg () {

    #  
    case $# in
    0)
        echo "a" >> /dev/null
        return 1
        ;;
    1)
        echo "a" >> /dev/null
        ;;
    *)
        echo "a" >> /dev/null
        usage
        return 2
        ;;
    esac
}

###

while getopts “hVvc:w:” OPTION
do
    case $OPTION in
        h)
            usage
            exit
            ;;
        V)
            echo "Version: $VERSION"
            exit
            ;;
        v)
            VERBOSE=1
            ;;
        c)
            C=$OPTARG
            CRITICAL=$C
            VERBTEXT="$VERBTEXT Critical level set to $CRITICAL days. "
            ;;
        w)
            W=$OPTARG
            WARNING=$W
            VERBTEXT="$VERBTEXT Warning level set to $WARNING days. "
            ;;
        ?)
            usage
            exit
            ;;
    esac
done

### ===================

function CheckLicense() {

#
BASEDIR="/etc"
PRODUCTS="zorp zcv zas zms"
LICFILE="license.txt"
#

for PRODUCT in $PRODUCTS; do

    if [ -e $BASEDIR/$PRODUCT/$LICFILE ]; then
        VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license found. "

        if [ 0 -eq `cat $BASEDIR/$PRODUCT/$LICFILE | grep "Valid-Not-After" | wc -l` ]; then
            VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license expire date not found, unlimited. "
            OUTTEXT="$OUTTEXT OK: `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license time is unlimited;  "

        else
            VALID=`cat $BASEDIR/$PRODUCT/$LICFILE | grep "Valid-Not-After" | cut -d" " -f2`
            VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license expire date: $VALID;  "

            EXPIRED=`date --utc --date "$VALID" +%s`
            TODAY=`date --utc +%Y/%m/%d`
            TODAY=`date --utc --date "$TODAY" +%s`
            let UNEXPIRED=($EXPIRED-$TODAY)/86400

            VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license expire days: $UNEXPIRED;  "

            if [ $UNEXPIRED -le $CRITICAL ]; then
                VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license expire days less than \"Critical\", $CRITICAL; "

                if [ $RETURN -le 2 ]; then
                    RETURN="2"
                    if [ $UNEXPIRED -lt 0 ]; then
                        OUTTEXT="$OUTTEXT Critical: `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license expired on $VALID; "
                    else
                        OUTTEXT="$OUTTEXT Critical: `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license will expire in $UNEXPIRED days; "
                    fi
                fi

            elif [[ ( $UNEXPIRED -lt $CRITICAL ) || ( $UNEXPIRED -le $WARNING ) ]] ; then
                VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license expire days beetween \"warning\" and \"critical\", $WARNING-$CRITICAL; "

                if [ $RETURN -le 1 ]; then
                    RETURN="1"
                    OUTTEXT="$OUTTEXT Warning: `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license will expire in $UNEXPIRED days; "
                fi

            elif [ $UNEXPIRED -gt $WARNING ]; then
                OUTTEXT="$OUTTEXT OK: `echo $PRODUCT | tr "[a-z]" "[A-Z]"`; "
                VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license will expire $UNEXPIRED days; "

            else
                VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license expire date state unknown; "

                if [ $RETURN -le 3 ]; then
                    if [ $RETURN -ne 2 ]; then
                        RETURN="3"
                    fi
                    OUTTEXT="$OUTTEXT Unknown: can't calculate `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license expire day; "
                fi
            fi
        fi
    else
        VERBTEXT="$VERBTEXT `echo $PRODUCT | tr "[a-z]" "[A-Z]"` license not found; "
    fi

done
}

### ===================

function Result () {

if [ 1 -eq $VERBOSE ] ; then
    echo $VERBTEXT
fi

echo $OUTTEXT
return $RETURN

}

### ====== Main ======

CheckLicense
Result
