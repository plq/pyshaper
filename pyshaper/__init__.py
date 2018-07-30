# encoding: utf8
#
# pyshaper - a dynamic traffic-shaper for Linux 2.4-2.6 based systems.
#
# Written in March 2004 by David McNab <david@freenet.org.nz>
# Copyright (c) 2004 by David McNab
#
# Released under the terms of the GNU General Public License.
#
# You should have received a file named 'COPYING' with this
# program. If not, you can review a copy of the GPL at the
# GNU website, at http://gnu.org
#

__version__ = '0.2.0-dev'

import re

# ---------------------------------------------
# Edit these constants if your situation requires it

configDir = "/etc/pyshaper"
configPath = "/etc/pyshaper/pyshaper.conf"

# how long between shaping runs, in seconds
shaperPeriod = 30

# where pyshaper sticks its pidfile
pidfile = "/var/run/pyshaper.pid"

# command we use to discover existing TCP connections
netstatCmd = "netstat -e -e -e -v --inet -p --numeric-ports"

# default verbosity of output messages
verbosity = 2

# -----------------------------------------------------------

reDelim = re.compile("[ ,:]")
reSpaces = re.compile("\\s+")
