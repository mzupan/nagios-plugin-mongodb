#!/usr/bin/env python

from setuptools import setup, find_packages
from pip.req import parse_requirements

setup(
    name="nagios-plugin-mongodb",
    description="A MongoDB availability and performance monitoring plugin for Nagios.",
    version="1.0.0",
    packages=find_packages(),
    url="https://github.com/mzupan/nagios-plugin-mongodb",
    maintainer="Mike Zupan",
    maintainer_email="mike@zcentric.com",
    author="Mike Zupan",
    author_email="mike@zcentric.com",
    scripts=["check_mongodb.py"],
    license="MIT",
    install_requires=[
      'pymongo',
      'setuptools>=3.4.0',
      'pip>=1.4'
    ],
    include_package_data=True
)
