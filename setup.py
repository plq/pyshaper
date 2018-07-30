from distutils.core import setup

# set this to the base path of your manpages
manpagesBaseDir = "/usr/share/man"

import sys, os

if os.getuid() != 0:
    print "Sorry, you must be root to install this program"
    sys.exit(1)

setup(
  name="pyshaper",
  version='0.1.1',
  description='Dynamic traffic-shaping app for Linux',
  author='David McNab',
  author_email='david@freenet.org.nz',
  url='http://www.freenet.org.nz/python/pyshaper',
  packages=[
    ],
  py_modules = [
    ],
  scripts=[
    "pyshaper",
    ],
  data_files=[
    ('/etc/pyshaper', ['pyshaper.conf', 'pyshaper.conf.readme']),
    (manpagesBaseDir+'/man8', ['pyshaper.8', 'pyshaper.conf.8']),
    ],
)

