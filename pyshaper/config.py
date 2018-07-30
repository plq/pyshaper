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

import time
import traceback

import os
import re

import pyshaper

from pyshaper.util import staticItemMatch


class ShaperConfig:
    """
    Loads/parses/edits/save the shaping config file
    """


    path = pyshaper.configPath

    forbidden = [
        'in',
        'out',
        'pri',
        'save',
        'matches',
        'classes',
        'subclasses',
        'expr',
        'bwIn',
        'bwOut',
        'name',
        'parent',
    ]

    shaperPeriod = pyshaper.shaperPeriod

    guiWidth = 200
    guiHeight = 200
    dontSave = False


    def __init__(self, path=None):

        self.reSpaces = re.compile("\\s+")

        if path:
            self.path = path

        if not os.path.isfile(self.path):
            raise Exception("Missing config file %s" % path)

        self.load()

        self.hasChanged = True


    def load(self):
        """
        Reloads the config, ditching old one
        """
        reComment = re.compile("#(.*)(\\n|$)")
        raw = file(self.path).read().strip()

        self.interfacesdict = {}
        self.interfaces = []

        # rip comments
        raw = reComment.sub("\n", raw)

        # join broken lines
        raw = re.sub("\\\\(\\s*)", "", raw)

        # break into lines, strip the lines, toss empties
        lines = [line.strip() for line in raw.split("\n")]
        lines = filter(lambda l: l != '', lines)

        cmds = []
        for line in lines:
            try:
                cmd, arg = self.reSpaces.split(line, 1)
                cmds.append((cmd, arg))
            except:
                traceback.print_exc()
                raise Exception \
                    ("Invalid line '%s' in config file %s" % (line, self.path))
        # print cmds

        # now the hard bit - make sense of these lines and stick them into rules base
        for item, val in cmds:
            self.execute(item, val)



    def execute(self, item, val=None):

        if val is None:
            item, val = self.reSpaces.split(item, 1)

        # print repr(item), repr(val)

        if item == 'period':
            self.shaperPeriod = int(val)
            return
        elif item == 'guiwidth':
            self.guiWidth = int(val)
            return
        elif item == 'guiheight':
            self.guiHeight = int(val)
            return

        try:
            ifname, rest = item.split(".", 1)
        except:
            print "Bad line in %s: %s %s" % (self.path, item, val)
            raise

        if ifname in self.forbidden:
            raise Exception("Illegal interface name '%s'" % ifname)

        # get interface rec, create if not previously known
        ifrec = self.interfacesdict.get(ifname, None)
        if not ifrec:
            ifrec = self.interfacesdict[ifname] = ShaperConfigIface(ifname)
            self.interfaces.append(ifrec)

        # process magic names
        if rest == 'in':
            ifrec.bwIn = float(val)
            return
        if rest == 'out':
            ifrec.bwOut = float(val)
            return
        if rest == 'ip':
            ifrec.ipaddr = val
            return

        # not magic - take as class name
        # print "rest=%s" % repr(rest)
        clsname, rest = rest.split(".", 1)

        if clsname in self.forbidden:
            raise Exception("Illegal class name '%s.%s'" % (ifname, clsname))

        # get class rec, create if not previously known
        clsrec = ifrec.classesdict.get(clsname, None)
        if not clsrec:
            clsrec = ifrec.classesdict[clsname] = ShaperConfigClass(ifrec, clsname)
            ifrec.classes.append(clsrec)

        # process magic names
        if rest in ['pri', 'priority']:
            clsrec.pri = int(val)
            return
        if rest == 'in':
            clsrec.bwIn = float(val)
            return
        if rest == 'out.rate':
            clsrec.bwOutRate = float(val)
            return
        if rest == 'out.ceil':
            clsrec.bwOutCeil = float(val)
            return
        if rest == 'test':
            clsrec.addTest(val)
            return
        if rest in ['raddr', 'rport', 'laddr', 'lport']:
            if rest.endswith('port'):
                val = int(val)
            setattr(clsrec, rest, val)
            return

        raise Exception \
            ("Invalid cmd field '%s' in %s.%s" % (rest, ifname, clsname))



    def save(self, hasChanged=False):
        """
        Writes the configuration out to disk, if changed
        """
        print "config.save: 1"
        if self.dontSave:
            return
        print "config.save: 2"
        if hasChanged:
            self.hasChanged = True
        print "config.save: 3"
        if not self.hasChanged:
            return

        print "saving config"

        path = self.path
        pathNew = path + ".sav"
        pathBak = path + ".bak"
        f = file(pathNew, "w")
        f.write("\n".join([
            "# pyshaper configuration file",
            "# ",
            "# (regenerated by pyshaper after realtime changes)",
            "# ",
            "# Updated: %s" % time.asctime(),
            "# ",
            "",

            "# width and height of GUI window - ignore this",
            "guiwidth %s" % self.guiWidth,
            "guiheight %s" % self.guiHeight,
            "",

            "# time period in seconds between each run",
            "period %s" % self.shaperPeriod,
            "",
            "",
            ]))

        for iface in self.interfaces:
            iface.save(f)
            f.write("\n")

        try:
            os.unlink(pathBak)
        except:
            pass
        os.rename(path, pathBak)
        os.rename(pathNew, path)
        self.hasChanged = False




    def __getattr__(self, name):
        """convenience for interactive debugging"""
        if name in ['__nonzero__', '__len__']:
            raise AttributeError(name)
        try:
            return self.interfacesdict[name]
        except:
            raise Exception("No such interface '%s'" % name)


    def __str__(self):

        return "\n".join([str(i) for i in self.interfaces])


    def __repr__(self):

        return str(self)




class ShaperConfigIface:
    """
    Holds the config info for a specific interface
    """


    bwIn = 1024 * 1024   # default 1Gbit/sec - ridiculous
    bwOut = 1024 * 1024


    def __init__(self, name):

        self.name = name

        self.classesdict = {}
        self.classes = []

        self.staticclassesdict = {}
        self.staticclasses = []

        dflt = self.default = self.classesdict['default'] = ShaperConfigClass \
            (self, 'default')
        dflt.bwIn = self.bwIn
        dflt.bwOut = self.bwOut

        self.ipaddr = '0.0.0.0'


    def __getattr__(self, name):
        """convenience for interactive debugging"""

        if name == 'parent':
            class P: pass
            p = P()
            p.name = '?'
            return p
        if name in ['__nonzero__', '__len__']:
            raise AttributeError(name)
        try:
            return self.classesdict[name]
        except:
            raise Exception("%s: No such class '%s'" % (self.name, name))



    def __setattr__(self, attr, value):

        self.__dict__[attr] = value

        if attr in ['bwIn', 'bwOut']:
            setattr(self.default, attr, value)


    def __str__(self):

        s = "%s: ip=%s in=%s out=%s" % \
        (self.name, self.ipaddr, self.bwIn, self.bwOut)
        if self.classes:
            s += "\n" + "\n".join([str(cls) for cls in self.classes])
        s += "\n" + str(self.default)
        return s

    def __repr__(self):
        return str(self)

    def save(self, f):
        """
        Saves this interface record out to open file f
        """
        name = self.name
        f.write("\n".join([
            "%s.ip %s" % (name, self.ipaddr),
            "%s.in %s" % (name, self.bwIn),
            "%s.out %s" % (name, self.bwOut),
        ]) + "\n")
        for cls in self.classes:
            cls.save(f)
        self.default.save(f)


class ShaperConfigClass:
    """
    Holds a config record for a specific class on a specific
    interface
    """

    pri = 1
    mode = 'dynamic'

    # attributes for 'static mode' shaping
    raddr = None
    rport = None
    laddr = None
    lport = None

    # window size in seconds for calculating rates
    rateWindow1 = 5.0

    def __init__(self, parent, name):

        self.parent = parent
        self.name = name
        # self.subclassesdict = {}
        # self.subclasses = []

        self.conns = []
        self.oldconns = []

        self.tests = []
        self.exprs = []

        # these lists are for dynamic monitoring via the gui
        self.pktInHist = []  # list of (time, size) tuples for inbound pkts
        self.pktOutHist = []  # ditto for outbound packets

        self.rateIn = 0.0
        self.rateOut = 0.0

        self.silly = "xxx"

    def __getattr__(self, name):
        """
        convenience for interactive debugging
        """
        if name == 'parent':
            return "?"
        parent = self.parent
        if name == 'bwIn':
            return parent.bwIn
        if name == 'bwOutRate':
            return parent.bwOut / 2
        if name == 'bwOutCeil':
            return parent.bwOut
        if name == 'ipaddr':
            self.ipaddr = parent.ipaddr
            return parent.ipaddr

        if name in ['__nonzero__', '__len__']:
            raise AttributeError(name)

        # try:
        #    return self.subclassesdict[name]
        # except:
        #    raise Exception("%s.%s: No such subclass '%s'" % (self.parent.name, self.name, name))

    def __setattr__(self, attr, val):
        """
        Setting any of the attributes 'raddr', 'rport', 'laddr', 'lport'
        converts this object into a 'static class', which means that it
        gains precedence for matching connections
        """
        # set the attrib
        self.__dict__[attr] = val

        # switch to static mode if a static attrib has been set
        if attr in ['raddr', 'rport', 'laddr', 'lport']:
            self.__dict__['mode'] = 'static'

    def __str__(self):

        hdr = "%s.%s: pri=%s in=%s out=%s/%s" % (
            self.parent.name, self.name,
            self.pri,
            self.bwIn, self.bwOutRate, self.bwOutCeil
        )

        if self.name == 'default':
            return hdr

        hdr1 = "\n    STATIC:"
        hdr2 = ''
        if self.raddr:
            hdr2 += " raddr=%s" % self.raddr
        if self.rport:
            hdr2 += " rport=%s" % self.rport
        if self.lport:
            hdr2 += " lport=%s" % self.lport
        if hdr2:
            hdr1 += hdr2
        else:
            hdr1 = "\n    ** NO STATIC RULE **"

        if self.exprs:
            hdr1 += "\n  " + "\n".join(["  " + expr for expr in self.exprs])
        else:
            hdr1 += "\n    ** NO DYNAMIC RULES **"

        return hdr + hdr1

    def __repr__(self):

        return repr(str(self))

    def addTest(self, expr):
        """
        Adds a test to this bw class
        """
        # convert expr into a valid lambda func
        self.exprs.append(expr)
        try:
            for term in ['cc', 'country',
                         'cmd', 'args',
                         'laddr', 'lport', 'raddr', 'rport',
                         'user']:
                expr = expr.replace(term, 'f.' + term)
            test = eval("lambda f:" + expr)
            self.tests.append(test)
        except:
            traceback.print_exc()
            raise Exception("Invalid test expression '%s'" % expr)

    def save(self, f):
        """
        Saves this class record out to open file f
        """
        name = self.parent.name + "." + self.name
        f.write("\n".join([
            "",
            "  # traffic class '%s' on interface '%s'" % (
            self.name, self.parent.name),
            "  %s.in %s" % (name, self.bwIn),
            "  %s.out.rate %s" % (name, self.bwOutRate),
            "  %s.out.ceil %s" % (name, self.bwOutCeil),
            "  %s.pri %s" % (name, self.pri),
        ]) + "\n")

        if self.exprs:
            f.write("  # dynamic matching rules\n")
            for e in self.exprs:
                f.write("  %s.test %s\n" % (name, e))
        if self.raddr or self.rport or self.laddr or self.lport:
            f.write("  # static matching specs\n")
            for a in ['raddr', 'rport', 'laddr', 'lport']:
                v = getattr(self, a)
                if v:
                    f.write("  %s.%s %s\n" % (name, a, v))

    def matches(self, connrec):
        """
        Tests if a connection matches the rule of one or more of our subclasses

        connrec is an item of class TCPConns

        Returns True if matches, False if not
        """
        m = staticItemMatch

        if 0 and self.name == 'local-apache' and connrec.rport != 22 and connrec.lport != 25:
            print "configclass.matches: ", [getattr(self, x) for x in
                                            ['raddr', 'rport', 'lport']]
            print "configclass.matches: connrec=%s" % repr(connrec)
            print repr(self.raddr), repr(self.rport), repr(self.lport)

        if self.mode == 'static':
            # only match the static flow attributes that have been set for this class
            if (m(self.raddr, connrec.raddr)
                    and m(self.rport, connrec.rport)
                    and m(self.lport, connrec.lport)
            ):
                if 0 and self.name == 'local-apache':
                    print "ShaperConfigClass.matches: %s: got static match" % self.name
                return True

        if self.mode == 'dynamic':
            for matches in self.tests:
                if matches(connrec):
                    if 0 and self.name == 'local-apache':
                        print "ShaperConfigClass.matches: %s: got dynamic match" % self.name
                    return True
            return False

    def matchesPacket(self, src, sport, dst, dport, dynamic=False):
        """
        return True if a packet, specified  by src, sport, dst, dport matches either
        our static rule, or matches one or more connections currently known to this class
        """
        f = staticItemMatch

        if 0:
            if self.name == 'local-apache' and sport not in [22,
                                                             25] and dport not in [
                22, 25]:
                raddr = self.raddr
                rport = self.rport
                laddr = self.laddr
                lport = self.lport

                print "----vvv----------------------"
                print "cls.matchesPacket: trying to match packet %s:%s->%s:%s against class %s" % (
                    repr(src), repr(sport), repr(dst), repr(dport), self.name)
                print "mode=%s" % self.mode
                print "raddr=%s rport=%s laddr=%s lport=%s" % (
                    repr(raddr), repr(rport), repr(laddr), repr(lport))
                print "----^^^----------------------"

        # test for dynamic match
        # print "-------------------"
        if dynamic:
            for conn in self.conns:
                # print "XXX", conn
                if conn.matchesPacket(src, sport, dst, dport):
                    # print "dynamic match %s: %s:%s -> %s:%s" % (
                    #    self.name, src, sport, dst, dport)
                    return True
        else:
            # test for static match
            if self.mode == 'static':
                raddr = self.raddr
                rport = self.rport
                laddr = self.laddr
                lport = self.lport

                if ((f(raddr, src) and f(rport,
                                         sport) and self.ipaddr == dst and f(
                        lport, dport))
                        or
                        (f(raddr, dst) and f(rport,
                                             dport) and self.ipaddr == src and f(
                            lport, sport))
                ):
                    # print "static match %s: %s:%s -> %s:%s" % (
                    #    self.name, src, sport, dst, dport)
                    return True

        # nothing matches
        return False

    def on_packet(self, src, sport, dst, dport, plen):

        # print "class %s.%s got packet %s:%s -> %s:%s %s" % (
        #    self.parent.name, self.name, src, sport, dst, dport, plen)

        dt = self.rateWindow1
        now = time.time()
        then = now - dt
        self.lastPktTime = now

        ipaddr = self.ipaddr
        pktInHist = self.pktInHist
        pktOutHist = self.pktOutHist

        # save packet in inbound and/or outbound histories
        item = (now, plen)
        if dst == ipaddr:
            pktInHist.insert(0, item)
        if src == ipaddr:
            pktOutHist.insert(0, item)

        # calculate current in and out rates
        i = 0
        totIn = 0
        for when, size in pktInHist:
            if when < then:
                break
            totIn += size
            i += 1
        self.rateIn = totIn / dt  # determine moving avg in
        del pktInHist[i:]

        i = 0
        totOut = 0
        for when, size in pktOutHist:
            if when < then:
                break
            totOut += size
            i += 1
        self.rateOut = totOut / dt  # determine moving avg in
        del pktOutHist[i:]

        # print "%s.%s: rate = %s b/s in, %s b/s out" % (
        #    self.parent.name, self.name, self.rateIn, self.rateOut)

        # self.pktInHist = []   # list of (time, size) tuples for inbound pkts, in reverse order
        # self.pktOutHist = []  # ditto for outbound packets

        self.silly = "yyy"

    def sortConnections(self):
        """
        Sorts connections into a predetermined order, so that if the
        set of eligible connections is the same, the sequence
        of tc commands will be the same
        """

        def sortconn(conn1, conn2):

            if conn1.raddr < conn2.raddr:
                return -1
            elif conn1.raddr > conn2.raddr:
                return 1
            elif conn1.rport < conn2.rport:
                return -1
            elif conn1.rport > conn2.rport:
                return 1
            elif conn1.laddr < conn2.laddr:
                return -1
            elif conn1.laddr > conn2.laddr:
                return 1
            elif conn1.lport < conn2.lport:
                return -1
            elif conn1.lport > conn2.lport:
                return 1
            return 0

        self.conns.sort(sortconn)




