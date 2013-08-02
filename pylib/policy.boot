############################################################################
##
## Copyright (c) 2000-2001 BalaBit IT Ltd, Budapest, Hungary
## All rights reserved.
##
## $Id: policy.boot,v 1.9 2003/05/30 15:40:15 bazsi Exp $
##
############################################################################

import sys
sys.dont_write_bytecode = True

# All modules referenced from C have to be imported here
import Zorp.Zorp, Zorp.SockAddr, Zorp.Stream

#print "Policy bootstrapping..."
