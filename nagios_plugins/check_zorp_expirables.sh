#!/bin/bash
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
