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

import commands
import getopt
import popen2
import sha
import signal
import time
import traceback
import os
import re
import sys

from pyshaper import configDir, configPath, shaperPeriod, verbosity


class TShaper:
    """
    Implements tc-based traffic shaping
    """

    dir = configDir
    configPath = configPath

    shaperPeriod = shaperPeriod  # do a shaping run every few seconds

    debug = False
    verbosity = verbosity

    def __init__(self, *args, **kw):

        # ensure we are root
        if os.getuid() != 0:
            raise Exception("You must be root to run this program")

        # reload sentinel
        self.reloadFlag = False

        # load initial config
        self.config = ShaperConfig(os.environ.get("PYSHAPERCONFIG", None))
        self.shaperPeriod = self.config.shaperPeriod

        self.verbosity = kw.get('verbosity', self.verbosity)
        self.debug = kw.get('debug', self.debug)

        # set up 'queue' of commands to execute, if not verbose
        if not self.debug:
            self.cmdq = []
            self.cmdBuf = ''
            self.cmdBufOld = ''
            self.cmdBufHash = ''
            self.cmdBufHashOld = ''

    def run(self):
        """
        Sits in a loop, periodically examining the current
        connections, applying user-given rules, and issuing
        shaping commands
        """
        # terminate sentinel
        self.quitFlag = False

        # reload sentinel
        self.reloadFlag = False

        # check for existing instance
        if os.path.isfile(pidfile):
            print "pyshaper pid file %s exists, pyshaper is likely running" % pidfile
            print "If you are sure pyshaper is not running, delete this"
            print "file and try again"
            sys.exit(1)

        # print self.config

        # create pidfile
        file(pidfile, "w").write(str(os.getpid()))

        # enable signal handler
        signal.signal(signal.SIGQUIT, self.sigHandler)
        signal.signal(signal.SIGHUP, self.sigHandler)
        signal.signal(signal.SIGTERM, self.sigHandler)

        self.log(2, "version %s now running on %s second cycle..." % (
            version, self.config.shaperPeriod))

        try:
            while not self.quitFlag:

                # do a run of shaping
                self.setupShaping()

                # wait a bit
                i = 0
                while i < self.shaperPeriod:
                    # reload config if needed
                    if self.reloadFlag:
                        self.log(2, "RELOADING CONFIG")
                        self.config.load()
                        self.shaperPeriod = self.config.shaperPeriod
                        self.reloadFlag = False
                        break
                    if self.quitFlag:
                        break
                    time.sleep(1)
                    i += 1

        except KeyboardInterrupt:
            # user pressed control-C - remove shaping
            print "Shaping terminated by keyboard interrupt"

        except:
            traceback.print_exc()
            print "pyshaper terminated"

        else:
            # quit flag got set
            print "Shaping terminated by kill signal"

        self.terminateShaping(immediate=True)
        try:
            os.unlink(pidfile)
        except:
            pass

    def sigHandler(self, signum, frame):

        if signum in [signal.SIGQUIT, signal.SIGTERM]:
            self.quitFlag = True
        elif signum == signal.SIGHUP:
            self.reloadFlag = True

    def setupShaping(self):
        """
        Generates and executes actual tc shaping commands,
        according to current setup
        """
        # get table of current connections
        self.currentConns = TCPConns()

        # self.currentConns.dump()

        # set up the dynamic shaping
        self.setupDynamic()

    def setupDynamic(self):
        """
        Creates/runs rules for dynamic (current-connection-based) shaping
        as configured.
        """
        # start the minor class ids at 100
        next_clsid = 100

        self.log(3, "---------- setupDynamic: start ------------")

        # first pass - backup connections lists, sort classes into static and dynamic
        for iface in self.config.interfaces:
            for cls in iface.classes:
                cls.oldconns = cls.conns
                cls.conns = []
            iface.default.oldconns = iface.default.conns
            iface.default.conns = []

            iface.staticClasses = filter(lambda c: c.mode == 'static',
                                         iface.classes)

        # second pass - classify all connections
        for conn in self.currentConns:
            # print conn.laddr, conn.lport, conn.raddr, conn.rport
            try:
                localip = conn.laddr

                # match against each rule
                for iface in self.config.interfaces:
                    # ditch connections that aren't on this interface
                    if iface.ipaddr != localip:
                        continue

                    # ignore connection if it matches a static class
                    for cls in iface.staticClasses:
                        if cls.matches(conn):
                            raise MatchedConnectionException

                    # try to match against all classes
                    for cls in iface.classes:
                        if cls.matches(conn):
                            self.log(3, "MATCH:\n  %s\n  %s" % (
                                str(conn), str(cls).replace("\n", "\n    ")))
                            cls.conns.append(conn)
                            raise MatchedConnectionException  # bail out to uppermost loop
                    # no rule found for conn, add to default
                    iface.default.conns.append(conn)
                    break  # quicker than raising exception

            except MatchedConnectionException:
                pass

        # third pass - generate/execute shaping commands
        for iface in self.config.interfaces:
            dev = iface.name

            # clear out dev
            self.tcResetDev(dev)

            # basic interface setup
            self.tcAddQdisc(dev, "root handle 1: htb default 1000")
            self.tcAddClassHtb(dev=dev, parent="1:", classid="1:1", pri=1,
                               rate=iface.bwOut)
            self.tcAddQdisc(dev, "ingress handle ffff:")

            nextCls = 100

            # set up shaping for each class
            for cls in iface.classes:
                nextCls += 1

                # bail if not static and no matching rules
                if cls.mode != 'static' and not cls.conns:
                    continue

                # we have either static and/or dynamic defs

                # create an htb class with sfq
                self.tcAddHtbAndSfq(
                    dev=dev,
                    parent="1:1",
                    classid="1:%s" % nextCls,
                    handle="%s:" % nextCls,
                    pri=cls.pri,
                    rate=cls.bwOutRate,
                    ceil=cls.bwOutCeil,
                )

                if cls.mode == 'static':
                    # add egress filter
                    matches = []
                    if cls.raddr:
                        matches.append("dst %s" % cls.raddr)
                    if cls.rport:
                        matches.append("dport %s 0xffff" % cls.rport)
                    if cls.lport:
                        matches.append("src %s" % iface.ipaddr)
                        matches.append("sport %s 0xffff" % cls.lport)

                    self.tcAddFilterOut(
                        dev=dev,
                        parent="1:",
                        flowid="1:%s" % nextCls,
                        pri=cls.pri,
                        matches=matches
                    )

                    # add ingress policer
                    matches = []
                    if cls.raddr:
                        matches.append("src %s" % cls.raddr)
                    if cls.rport:
                        matches.append("sport %s 0xffff" % cls.rport)
                    if cls.lport:
                        matches.append("dst %s" % iface.ipaddr)
                        matches.append("dport %s 0xffff" % cls.lport)

                    self.tcAddFilterIngressPolice(
                        dev=dev,
                        rate=cls.bwIn,
                        pri=cls.pri,
                        flowid=nextCls,
                        matches=matches,
                        index=nextCls,
                    )

                # set up dynamic rules, if current conns match
                if cls.conns:

                    # put the connections into a deterministic order
                    cls.sortConnections()

                    # split up input bandwidth evenly amongst each connection
                    bwInPerConn = float(cls.bwIn) / len(cls.conns)

                    for conn in cls.conns:
                        self.log(4, "%s.%s" % (dev, cls.name))

                        # add egress filter
                        self.tcAddFilterOut(
                            dev=dev,
                            parent="1:",
                            flowid="1:%s" % nextCls,
                            pri=cls.pri,
                            matches=[
                                "src %s" % conn.laddr,
                                "sport %s 0xffff" % conn.lport,
                                "dst %s" % conn.raddr,
                                "dport %s 0xffff" % conn.rport,
                            ],
                        )

                        # add ingress policer
                        self.tcAddFilterIngressPolice(
                            dev=dev,
                            rate=bwInPerConn,
                            pri=cls.pri,
                            flowid=nextCls,
                            matches=[
                                "src %s" % conn.raddr,
                                "sport %s 0xffff" % conn.rport,
                                "dst %s" % conn.laddr,
                                "dport %s 0xffff" % conn.lport,
                            ],
                            index=nextCls,
                        )

            # set up interface default
            self.log(4, "DEFAULT for %s" % dev)
            default = iface.default
            self.tcAddHtbAndSfq(
                dev=dev, parent="1:1", classid="1:1000", handle="1000:",
                pri=default.pri, rate=default.bwOutRate, ceil=default.bwOutCeil)

            # self.tcAddFilterOut(
            #    dev=dev, parent="1:", flowid="1:1000",
            #    pri=default.pri, matches=["dst 0.0.0.0/0"])
            self.log(4, "DONE DEFAULT for %s" % dev)

            # if non-verbose, then we've got a shitload of commands to execute
            # and we need to pipe them in bulk to a shell
            if not self.debug:
                self.runCmdQ()

    def runCmdQ(self):

        # build a single string out of all the queued cmds
        self.cmdBuf = "\n".join(self.cmdq) + "\n"
        self.cmdBufHash = sha.new(self.cmdBuf).hexdigest()
        self.cmdq = []

        # bail if the command set hasn't changed
        self.log(4, "oldCmdBuf=%s" % self.cmdBufHashOld)
        self.log(4, "newCmdBuf=%s" % self.cmdBufHash)

        if self.cmdBuf == self.cmdBufOld:
            self.log(3, "runCmdQ: no change to tc command set - bailing")
            return
        if self.cmdBufOld != '':
            self.log(2, "connections have changed, rebuilding qdiscs")

        # fire off the commands to a shell child proc
        shOut, shIn = popen2.popen4("/bin/sh")
        shIn.write(self.cmdBuf)
        shIn.close()
        out = shOut.read()
        shOut.close()

        # save the command buf for future comparison
        self.cmdBufOld = self.cmdBuf

        # for debugging
        self.log(3, "SCRIPT:\n%sOUT:\n%s" % (self.cmdBuf, out))

    def terminateShaping(self, immediate=False):
        """clean existing down- and uplink qdiscs, hide errors"""
        # tc = self.tc

        for iface in self.config.interfaces:
            self.tcResetDev(iface.name, immediate=immediate)

        # tc("qdisc del DEV root")
        # tc("qdisc del DEV ingress")

    def status(self):

        tc = self.tc
        DEV = self.dev

        raw = tc("-s qdisc ls DEV") + tc("-s class ls DEV")
        return raw

    def tc(self, cmd, **kw):
        # cmd = "tc "+(cmd.replace("DEV", "dev "+self.dev))
        cmd = "tc " + cmd

        # creating a queue of commands
        self.cmdq.append(cmd)

        # in debug mode, we execute commands and report their results one at a time
        if self.debug or kw.get('immediate', False):
            self.log(3, cmd)
            res = commands.getoutput(cmd)
            if res:
                self.log(3, res)
            return res

    def tcResetDev(self, dev, immediate=False):

        tcDelQdisc = self.tcDelQdisc

        tcDelQdisc(dev, "root", immediate=immediate)
        tcDelQdisc(dev, "ingress", immediate=immediate)

    def tcDelQdisc(self, dev, name, immediate=False):

        self.tc("qdisc del dev %s %s" % (dev, name), immediate=immediate)

    def tcAddQdisc(self, dev, *args):

        self.tc("qdisc add dev %s %s" % (dev, " ".join(args)))

    def tcAddQdiscSfq(self, dev, parent, handle, perturb=10):

        self.tcAddQdisc(dev, "parent %s handle %s sfq perturb %s" % (
        parent, handle, perturb))

    def tcAddClass(self, dev, *args):

        self.tc("class add dev %s %s" % (dev, " ".join(args)))

    def tcAddClassHtb(self, dev, parent, classid, pri, rate, ceil=None):

        if ceil:
            self.tcAddClass(
                dev,
                "parent %s classid %s htb rate %s ceil %s burst 6k prio %s" % (
                    parent, classid, int(rate * 1024), int(ceil * 1024), pri)
            )
        else:
            self.tcAddClass(
                dev,
                "parent %s classid %s htb rate %s burst 6k prio %s" % (
                    parent, classid, int(rate * 1024), pri)
            )

    def tcAddHtbAndSfq(self, dev, parent, classid, handle, pri, rate,
                       ceil=None):

        if not ceil:
            ceil = self.config.interfaces[dev].bwOut

        self.tcAddClassHtb(dev=dev, parent=parent, classid=classid, pri=pri,
                           rate=rate, ceil=ceil)
        self.tcAddQdiscSfq(dev=dev, parent=classid, handle=handle)

    def tcAddFilter(self, dev, *args):

        self.tc("filter add dev %s %s" % (dev, " ".join(args)))

    def tcAddFilterOut(self, dev, parent, flowid, pri, matches):

        self.tcAddFilter(
            dev,
            "parent %s" % parent,
            "protocol ip prio %s u32" % pri,
            " ".join(["match ip " + m for m in matches]),
            "flowid %s" % flowid,
        )

        # tcAddFilter(self.dev, "parent 1: protocol ip prio 18 u32 match ip dst 0.0.0.0/0 flowid 1:10")

    def tcAddFilterIngressPolice(self, dev, rate, pri, flowid, matches, index):

        # if ingressMethod == 'share':
        #    indexfld = "index %s" % index
        # else:
        #    indexfld = ''

        self.tcAddFilter(
            dev,
            "parent ffff: protocol ip prio %s" % pri,
            "u32",
            " ".join(["match ip " + m for m in matches]),
            "police rate %s" % int(rate * 1024),
            # indexfld,
            "burst 10k drop flowid ffff:%s" % flowid,
        )

    def log(self, level, msg):

        if level > self.verbosity:
            return
        print "pyshaper: %s" % msg

