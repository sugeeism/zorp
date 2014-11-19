#sbin_SCRIPTS = zorpctl

sysconf_DATA = instances.conf.http.sample instances.conf.https.sample instances.conf.ssh.sample zorpctl.conf

pkgdatadir = @ZORPCTL_PYTHON_DIR@

pkgdata_DATA = __init__.py   \
	CommandResults.py    \
	Instances.py         \
	PluginAlgorithms.py  \
	ProcessAlgorithms.py \
	SZIGMessages.py      \
	szig.py              \
	UInterface.py        \
	utils.py             \
	ZorpctlConf.py

EXTRA_DIST = $(pkgdata_DATA) $(sysconf_DATA) $(sbin_SCRIPTS)
