#! /usr/bin/python
# -*- coding: utf-8 -*-

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

# Zorp running threads control in Nagios
# Created by Gabor Timar <gaboca@balabit.hu>

import sys
import subprocess

import csv
import StringIO

def instancesRead():	# Work with 'instances.conf'
	try:
		iFile = open('/etc/zorp/instances.conf','r')
	except:
		status = 'UNKNOWN'
		print status, '\n"instances.conf" cannot be read.'
		sys.exit(3)

	instList = []

	for iLine in iFile:
		if iLine[0] != '\n' and iLine[0] != '#':

			instParams = iLine.split()
			instName = instParams[0]

			if '--threads' in instParams:
				thIndex = instParams.index('--threads')
				threadMax = instParams[thIndex + 1]
			else:
				threadMax = 1000

			instLine = instName, threadMax
			instList.append(instLine)

	iFile.close()
	return instList
# --- def instancesRead() ---

def zorpctlStatusRead():	# Work with 'zorpctl gui-status'
	zCtlStatusStr = ''
	try:
		zCtlStatusStr = subprocess.Popen(['zorpctl', 'gui-status'], stdout=subprocess.PIPE).communicate()[0]
		zCtlStatusFile = StringIO.StringIO(zCtlStatusStr)
		statusList = csv.DictReader(zCtlStatusFile, dialect='zorpctl_guistatus')
                return  statusList
	except:
		status = 'CRITICAL'
		print status, '\n"zorpctl" problem.'
		sys.exit(2)
	

	return statusList
# --- def zorpctlStatusRead() ---

def checkZorpThreads():
	status = 'OK'
	critStr = ''
	warnStr = ''

	iConfList = instancesRead()	# 
	zCtlList = zorpctlStatusRead()	# 

	if verbose:	# Verbose mode
		print 'instances.conf:\n', iConfList, '\n'
		print 'zorpctl gui-status:\n', zCtlList, '\n'

	for configInst in iConfList:	# "instances.conf"
		hit = False
		for runningInst in zorpctlStatusRead():	# "zorpctl gui-status"
                        process = runningInst['process']
                        processNum = runningInst['processnum']
			instance = process[0:-len(processNum) - 1]
			pid = runningInst['pid']
			if configInst[0] == instance:
				hit = True
				if runningInst['status'] != 'running':	# Instance exists, but not running
					critStr = critStr +' '+ configInst[0]
					status = 'CRITICAL'
					if verbose:	# Verbose mode
						print status, configInst[0], '"status != running"'
					
				else:	# Instance létezik és fut is... vizsgáljuk tovább
					critThread = int(configInst[1]) * crit / 100
					warnThread = int(configInst[1]) * warn / 100
					runnThread = int(runningInst['running threads'])
			
					if verbose:	# Verbose mode
						print status, pid, 'warn:', warnThread, 'crit:', critThread
			
					if runnThread >= critThread:	# Critical value
						critStr = critStr +' '+ configInst[0]
						status = 'CRITICAL'
						if verbose:	# Verbose mode
							print status, configInst[0], pid, '>=', critThread
						break
			
					if runnThread >= warnThread and runnThread <= critThread:	# Tall value, but not critic
						warnStr = warnStr +' '+ configInst[0]
						if status == 'OK':
							status = 'WARNING'
						if verbose:	# Verbose mode
							print status, configInst[0],  warnThread, '>=', pid, '<', critThread
			
		if not hit:
			if verbose:	# Verbose mode
				print configInst[0], 'defined, but not running'
			critStr = critStr +' '+ configInst[0]
			status = 'CRITICAL'

		if len(critStr) == 0:
			if len(warnStr) > 0:
				statusStr = 'WARNING:' + warnStr
			else:
				statusStr = 'OK'
		else:
			if len(warnStr) > 0:
				statusStr = 'CRITICAL:' + critStr +'; ' + 'WARNING:' + warnStr + ';'
			else:
				statusStr = 'CRITICAL:' + critStr +'; '
			
		returnList = [status, statusStr]
	return returnList
# --- checkZorpThreads() ---	

def usage():
	print 'Usage:\n\t"check_zorp_threads.py -h"\tprint this help\n\t"check_zorp_threads.py -w X -c Y -v"\n\t\twhere "-w X" warning: X %; "-c Y" critical Y %; "-v" verbose mode (recommanded command line only!)'
	print 'Default warning:\t', warn, '%'
	print 'Default critical:\t', crit, '%'
	sys.exit(0)
# --- usage() ---

# ================
# Main program
# ================

verbose = False
warn = 75
crit = 90

if len(sys.argv) == 2 and sys.argv[1] == '-h':
	usage()

i = 0
while i < len(sys.argv):
	if sys.argv[i] == '-v':
		verbose = True
	try:
		if sys.argv[i] == '-c' and 0 < int(sys.argv[i+1]) < 100:
			crit = int(sys.argv[i+1])
	except:
		pass
	try:
		if sys.argv[i] == '-w' and 0 < int(sys.argv[i+1]) < 100:
			warn = int(sys.argv[i+1])
	except:
		pass
	i = i+1

if verbose:
	print 'Warning:', warn, '%;', 'Critical:', crit, '%;'

csv.register_dialect('zorpctl_guistatus', delimiter=';', quoting=csv.QUOTE_ALL, quotechar='"')
sumStatus, sumMsg = checkZorpThreads()
if sumStatus == 'CRITICAL':
	print sumMsg
	sys.exit(2)
if sumStatus == 'WARNING':
	print sumMsg
	sys.exit(1)
if sumStatus == 'OK':
	print 'OK'
	sys.exit(0)
# === Main program ===
