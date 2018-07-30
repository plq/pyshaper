# encoding: utf8
#
# pyshaper - a dynamic traffic-shaper for Linux 2.4-2.6 based systems.
#
# Run epydoc on this file to get reasonably readable API doco
#
# Run with the argument 'help' for usage info.
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

import getopt
import signal
import sys
import traceback

import os

import pyshaper
from pyshaper import configDir, reDelim
from pyshaper.conn import TCPConns

from pyshaper.gui import TShaperGui
from pyshaper.tshaper import TShaper


def main():
    # try to create pyshaper dir if nonexistent
    if not os.path.isdir(configDir):
        try:
            os.makedirs(configDir)
        except:
            pass

    argv = sys.argv
    argc = len(argv)

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "h?vdV:f",
                                   ['help', 'version', 'debug', 'foreground',
                                    'verbosity=',
                                    ])
    except:
        traceback.print_exc(file=sys.stdout)
        usage("You entered an invalid option")

    daemonise = True
    verbosity = 2
    debug = False

    for opt, val in opts:

        if opt in ['-h', '-?', '--help']:
            usage(True)

        elif opt in ['-d', '--debug']:
            debug = True

        elif opt in ['-f', '--foreground']:
            daemonise = False

        elif opt in ['-v', '--version']:
            print "pyshaper version %s" % pyshaper.__version__
            sys.exit(0)

        elif opt in ['-V', '--verbosity']:
            verbosity = int(val)

    #print "Debug - bailing"
    #print repr(opts)
    #print repr(args)
    #sys.exit(0)

    # Try to bring up GUI if no command given
    if len(args) == 0:
        mypid = os.getpid()
        try:
            g = TShaperGui()
        except:
            traceback.print_exc()
            print "No command given, cannot launch gui, not good - bailing"
            usage()
            sys.exit(1)
        try:
            g.run()
        except SystemExit, KeyboardInterrupt:
            print "killing self"
            os.kill(mypid, signal.SIGKILL)
            pass
        except:
            traceback.print_exc()
            print "pyshaper GUI crashed!"
            sys.exit(1)
        sys.exit(0)

    cmd = args[0]

    if cmd == 'help':
        usage(True)

    elif cmd == "start":
        if daemonise:
            pid = os.fork()
            if pid:
                print "pyshaper detached into background as daemon with pid %s" % pid
                sys.exit(0) # parent quit, leave child running
        try:
            shaper = TShaper(verbosity=verbosity, debug=debug)
            shaper.run()
        except:
            traceback.print_exc()
            print "Exception - terminating"
            sys.exit(1)

    #print shaper.currentConns[:]

    elif cmd == "status":
        shaper = TShaper()
        print shaper.status()
        sys.exit(0)

    elif cmd == 'netstat':
        cmd = pyshaper.netstatCmd
        if len(argv) == 3:
            cmd += "|grep %s" % argv[2]
        os.system(cmd)
        sys.exit(0)

    elif cmd == 'dumpconns':
        for conn in TCPConns():
            print conn.strdetail()
        sys.exit(0)

    elif cmd in ['reload', 'restart']:
        if os.path.isfile(pyshaper.pidfile):
            pid = int(file(pyshaper.pidfile).read())
            os.kill(pid, signal.SIGHUP)
            print "Sent SIGHUP to pyshaper (pid %s) to force config reload" % pid
            sys.exit(0)
        else:
            print "Can't find pidfile %s, pyshaper appears not to be running" % pyshaper.pidfile
            sys.exit(1)

    elif cmd in ['kill', 'stop']:
        if os.path.isfile(pyshaper.pidfile):
            pid = int(file(pyshaper.pidfile).read())
            os.kill(pid, signal.SIGQUIT)
            print "Terminated pyshaper (pid %s)" % pid
            sys.exit(0)
        else:
            print "Can't find pidfile %s, pyshaper appears not to be running" % pyshaper.pidfile
            sys.exit(1)



def usage(detailed=False):
    print "Usage: %s <options> <command>" % sys.argv[0]
    if not detailed:
        sys.exit(0)

    print "This is pyshaper, a dynamic traffic-shaping application written"
    print "by David McNab <david@freenet.org.nz>"
    print "Program homepage is at http://www.freenet.org.nz/python/pyshaper"
    print
    print "Options:"
    print "     -f, --foreground  - stay in foreground, and do not daemonise"
    print "     -h, --help        - display this help"
    print "     -v, --version     - print program version"
    print "     -V, --verbosity=n - set verbosity to n, default 2, 1==quiet, 4==noisy"
    print "     -d, --debug       - debug mode - severely impacts performance"
    print
    print "Commands:"
    print "     (run with no commands to launch the GUI)"
    print "     start  - start pyshaper running (as daemon, unless you give '-f'"
    print "     stop   - terminate any running instance of pyshaper"
    print "     status - do a status dump of pyshaper"
    print "     netstat [keyword] - runs the netstat cmd, optionally grepping for <keyword>"
    print "     reload - force the running instance of pyshaper to re-read"
    print "              its configuration file from /etc/pyshaper/pyshaper.conf,"
    print "              then rebuild the shaping rules"
    print "     help   - display this help"
    print

    sys.exit(0)
