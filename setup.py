#!/usr/bin/env python

from distutils.core import setup

setup(
    name='SoftEtherPy',
    version='1.0',
    description='Python Distribution Utilities',
    author='Pervolo',
    author_email='info@pervolo.com',
    url='https://github.com/mindcollapse/SoftEtherPy',
    packages=['distutils', 'distutils.command'],
    package_dir = {'': 'softether'}
)