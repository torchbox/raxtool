#! /usr/bin/env python

from distutils.core import setup
from pip.req import parse_requirements
import glob

install_reqs = parse_requirements('requirements.txt', session=False)
reqs = [str(ir.req) for ir in install_reqs]

setup(name='raxtool',
      version='1.0',
      description='Rackspace command-line tool and API',
      author='Torchbox sysadmin',
      author_email='sysadmin@torchbox.com',
      url='https://github.com/torchbox/raxtool',
      packages = [ 'rax' ],
      py_modules = [ fn[:-3] for fn in glob.glob('*.py') ],
      install_requires = reqs,
     )
