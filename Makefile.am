SUBDIRS = lib libproxy modules zorp pylib doc zorpctl scripts tests munin_plugins nagios_plugins
DIST_SUBDIRS = $(SUBDIRS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzorp.pc libzorpproxy.pc


pkgdatadir=@datadir@/zorp
pkgdata_DATA = moduledist.conf

EXTRA_DIST = dist.conf BUGS WHATIS.TXT VERSION ${pkgconfig_DATA} ${pkgdata_DATA}

COPYING: COPYING.in@PACKAGE_SUFFIX@
	cp $< $@

MAINTAINERCLEANFILES=dist.conf COPYING

dist.conf: dist.conf.in
	$(top_builddir)/config.status --file $@:$<
