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


import pyshaper


def staticItemMatch(item, test):
    """
    returns true if the first arg is None, or equal to second arg
    """
    return (item is None) or (item == test)


def takeKey(somedict, keyname, default=None):
    """
    Utility function to destructively read a key from a given dict.
    Same as the dict's 'takeKey' method, except that the key (if found)
    sill be deleted from the dictionary.
    """
    if somedict.has_key(keyname):
        val = somedict[keyname]
        del somedict[keyname]
    else:
        val = default
    return val


def splitflds(s):
    s = s.strip()
    if s == '':
        return []
    else:
        return pyshaper.reDelim.split(s)
