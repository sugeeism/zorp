nagiosdir = ${ZORP_NAGIOS_DIR}
nagios_SCRIPTS = check_zorp_licenses.sh check_zorp_threads.py check_zorp_expirables.sh

nagiosconfdir = ${ZORP_NAGIOS_CONF_DIR}
nagiosconf_DATA = zorp.cfg

sudoconfdir = ${ZORP_SUDOERSD_CONF_DIR}
sudoconf_DATA = zorp_nagios_plugins

EXTRA_DIST = ${nagios_SCRIPTS} ${nagiosconf_DATA} ${sudoconf_DATA}

install-data-hook:
	mkdir -p $(DESTDIR)$(sudoconfdir)
	$(INSTALL) -c -m 440 $(addprefix $(srcdir)/,$(sudoconf_DATA)) $(DESTDIR)$(sudoconfdir)
