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


import os, re

from setuptools import setup
from setuptools import find_packages


PACKAGE_NAME = 'pyshaper'

v = open(os.path.join(os.path.dirname(__file__), PACKAGE_NAME, '__init__.py'))
VERSION = re.compile(r'.*__version__ = ["\'](.*?)["\']', re.S) \
                                                       .match(v.read()).group(1)

MANPAGES_BASE_DIR = "/usr/share/man"

setup(
    name=PACKAGE_NAME,
    version=VERSION,
    description='Dynamic traffic-shaping app for Linux',
    author='David McNab',
    author_email='david@freenet.org.nz',
    url='http://www.freenet.org.nz/python/pyshaper',
    packages=find_packages(),
    install_requires=['Pmw'],
    entry_points=dict(
        console_scripts=[
            "pyshaper=pyshaper.main:main",
        ],
    ),
    data_files=[
        ('/etc/pyshaper', ['pyshaper.conf', 'pyshaper.conf.readme']),
        (MANPAGES_BASE_DIR + '/man8', ['pyshaper.8', 'pyshaper.conf.8']),
    ],
)
