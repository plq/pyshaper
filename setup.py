
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
