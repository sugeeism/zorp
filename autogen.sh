#!/bin/sh
#
# Run this script to generate Makefile skeletons and configure
# scripts.
#

libtoolize -f
aclocal
autoheader
autoconf
automake --add-missing --foreign
