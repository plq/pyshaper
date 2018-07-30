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

import re, popen2


class MatchedConnectionException(Exception):
    pass


class IPmon:

    def __init__(self, handler=None):

        if not handler:
            handler = self.defaultHandler
        self.handler = handler

        self.conns = {}

    def run(self):

        reSpaces = re.compile("\\s+")
        tOut, tIn = popen2.popen2("tcpdump -vnl", 1024)

        while 1:
            try:
                line = line0 = tOut.readline().strip()

                # print line
                # continue

                line = reSpaces.split(line, 1)[1]

                if line.startswith("arp"):
                    continue

                try:
                    addrs, rest = line.split(":", 1)
                except:
                    continue

                addrs = addrs.strip()
                src, dst = addrs.split(" > ")

                # print "src=%s dst=%s" % (repr(src), repr(dst))

                srcbits = src.split(".")
                src = ".".join(srcbits[:4])
                if len(srcbits) == 5:
                    sport = int(srcbits[-1])
                else:
                    sport = 0

                dstbits = dst.split(".")
                dst = ".".join(dstbits[:4])
                if len(dstbits) == 5:
                    dport = int(dstbits[-1])
                else:
                    dport = 0

                pktlen = int(rest[:-1].split(" ")[-1])

                # print "---------------------------"
                # print line

                k = '%s:%s>%s:%s' % (src, sport, dst, dport)
                conns = self.conns
                if not conns.has_key(k):
                    conns[k] = 0
                conns[k] += pktlen

                pkt = {'src': src, 'sport': sport,
                       'dst': dst, 'dport': dport,
                       'len': pktlen, 'total': conns[k]}
                # print "IPmon: pkt=%s" % pkt
                self.handler(pkt)

            except KeyboardInterrupt:
                print "IPmon: got kbd int"
                return

            except:
                # traceback.print_exc()
                # print "IPmon exception"
                # print line0
                pass

    def runPcap(self):

        p = pcap.pcapObject()
        dev = "eth0"

        net, mask = pcap.lookupnet(dev)
        # note:  to_ms does nothing on linux
        p.open_live(dev, 1600, 0, 100)
        # p.dump_open('dumpfile')

        # p.setfilter(string.join(sys.argv[2:],' '), 0, 0)

        # try-except block to catch keyboard interrupt.  Failure to shut
        # down cleanly can result in the interface not being taken out of promisc.
        # mode
        # p.setnonblock(1)
        while 1:
            try:
                p.dispatch(1, self.pcapCallback)
            except KeyboardInterrupt:
                print '%s' % sys.exc_type
                print 'shutting down'
                print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
                return
            except:
                traceback.print_exc()

    def pcapCallback(self, pktlen, data, timestamp):

        if not data:
            return

        if data[12:14] == '\x08\x00':
            decoded = self.pcapDecode(data[14:])
            print '\n%s.%f %s > %s' % (time.strftime('%H:%M',
                                                     time.localtime(timestamp)),
                                       timestamp % 60,
                                       decoded['source_address'],
                                       decoded['destination_address'])
            for key in ['version', 'header_len', 'tos', 'total_len', 'id',
                        'flags', 'fragment_offset', 'ttl']:
                print '  %s: %d' % (key, decoded[key])

    def pcapDecode(self, s):

        d = {}
        d['version'] = (ord(s[0]) & 0xf0) >> 4
        d['header_len'] = ord(s[0]) & 0x0f
        d['tos'] = ord(s[1])
        d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
        d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
        d['flags'] = (ord(s[6]) & 0xe0) >> 5
        d['fragment_offset'] = socket.ntohs(
            struct.unpack('H', s[6:8])[0] & 0x1f)
        d['ttl'] = ord(s[8])
        d['protocol'] = ord(s[9])
        d['checksum'] = socket.ntohs(struct.unpack('H', s[10:12])[0])
        d['source_address'] = pcap.ntoa(struct.unpack('i', s[12:16])[0])
        d['destination_address'] = pcap.ntoa(struct.unpack('i', s[16:20])[0])
        if d['header_len'] > 5:
            d['options'] = s[20:4 * (d['header_len'] - 5)]
        else:
            d['options'] = None
        d['data'] = s[4 * d['header_len']:]
        return d

    def defaultHandler(self, pkt):

        print "%s:%s => %s:%s %s %s" % (pkt['src'], pkt['sport'],
                                        pkt['dst'], pkt['dport'],
                                        pkt['len'], pkt['total'])



