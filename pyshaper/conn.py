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
import traceback

import pyshaper
from pyshaper.util import staticItemMatch

try:
    import GeoIP
except ImportError:
    GeoIP = None


class Conn:
    """
    Simple class representing a single current TCP connection
    """
    def __str__(self):

        if GeoIP:
            return "%s/%s %s:%s => %s:%s (%s/%s)" % (
                self.user, self.pid,
                self.laddr, self.lport, self.raddr, self.rport,
                self.cc, self.country)
        else:
            return "%s/%s %s:%s => %s:%s" % (
                self.user, self.pid,
                self.laddr, self.lport, self.raddr, self.rport,
            )

    def __repr__(self):
        return str(self)

    def strdetail(self):
        return str(self) + " (%s %s)" % (
            self.cmd, " ".join(["' " + arg +"'" for arg in self.args]))

    def matchesPacket(self, src, sport, dst, dport):
        """
        Returns True if a packet matches this connection
        """
        raddr = self.raddr
        rport = self.rport
        laddr = self.laddr
        lport = self.lport

        # print "Conn: matching %s:%s->%s:%s against %s:%s,%s:%s" % (
        #    repr(src), repr(sport), repr(dst), repr(dport),
        #    repr(raddr), repr(rport), repr(laddr), repr(lport))
        m = staticItemMatch

        if ((m(raddr, src) and m(rport, sport) and m(lport, dport))
                or
                (m(raddr, dst) and m(rport, dport) and m(lport, sport))
        ):
            # print "Conn.matchesPacket: true"
            return True
        else:
            return False




class TCPConns:
    """
    Class which scans the current TCP connections, and returns a
    list with a dict representing each connection
    """


    netstatCmd = pyshaper.netstatCmd



    def __init__(self):

        if GeoIP:
            # create a GeoIP object, enable country lookups
            try:
                g = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
                self.ip2cc = g.country_code_by_addr
                self.ip2country = g.country_name_by_addr
            except:
                self.ip2cc = None
                self.ip2country = None
                traceback.print_exc()
        else:
            self.ip2cc = None
            self.ip2country = None

        self.getconns()


    def getconns(self):

        # run 'netstat', break output into lines
        lines = commands.getoutput(self.netstatCmd).strip().split("\n")

        # and break each line into fields
        lines = [pyshaper.reSpaces.split(l) for l in lines]

        ip2cc = self.ip2cc
        ip2country = self.ip2country

        conns = []
        for line in lines:
            try:
                if line[0] == 'tcp':
                    d = Conn()
                    localend = line[3].split(":")
                    d.laddr = localend[0]
                    d.lport = int(localend[1])
                    remend = line[4].split(":")
                    raddr = remend[0]
                    d.raddr = raddr
                    d.rport = int(remend[1])
                    d.user = line[6]
                    d.inode = int(line[7])
                    proc = line[8].split("/")
                    d.pid = int(proc[0])
                    cmdline = file("/proc/%s/cmdline" % d.pid) \
                                                   .read().strip().split("\x00")
                    if cmdline[-1] == '':
                        cmdline.pop()
                    d.cmd = cmdline[0]
                    d.args = cmdline[1:]
                    if ip2cc:
                        try:
                            d.cc = ip2cc(raddr)
                        except:
                            d.cc = None
                    if ip2cc:
                        try:
                            d.country = ip2country(raddr)
                        except:
                            d.country = None
                    conns.append(d)
            except:
                # print "hates %s" % repr(line)
                # traceback.print_exc()
                pass
        self.conns = conns



    def dump(self):

        for conn in self:
            print str(conn)


    def __getitem__(self, item):
        return self.conns[item]


    def __getslice__(self, fromidx, toidx):
        return self.conns[fromidx:toidx]


    def __len__(self):
        return len(self.conns)


    def filter(self, **kw):
        conns = []
        for conn in self:
            matches = True
            for k ,v in kw.items():
                if conn[k] != v:
                    matches = False
                    break
            if matches:
                conns.append(conn)
        return conns


