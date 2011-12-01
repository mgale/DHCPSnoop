#!/usr/bin/env python
#
# Copyright 2011 DHCPSnoop
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import distutils.core
import sys
# Importing setuptools adds some features like "setup.py develop", but
# it's optional so swallow the error if it's not there.
try:
    import setuptools
except ImportError:
    pass

kwargs = {}

extensions = []
major, minor = sys.version_info[:2]
version = "2.0git"

if major >= 3:
    import setuptools  # setuptools is required for use_2to3
    kwargs["use_2to3"] = True

distutils.core.setup(
    name="dhcpsnoop",
    version=version,
    packages = ["dhcpsnoop.py"],
    package_data = {
        },
    ext_modules = extensions,
    author="MichaelGale",
    author_email="gale.michael@gmail.com",
    download_url="http://github.com/dhcpsnoop/",
    license="http://www.apache.org/licenses/LICENSE-2.0",
    description="DHCPSnoop is used to monitor DHCP servers",
    **kwargs
)
