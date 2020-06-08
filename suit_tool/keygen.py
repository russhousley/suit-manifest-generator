#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2019 ARM Limited or its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------
import os
import pyhsslms

def main(options):
    # ES256 private key generation
    if options.type == 'secp256r1':
        pass

    # HSS-LMS private key generation
    elif options.type == 'hss-lms':
        options.private_key.close()
        os.remove(options.private_key.name)
        keyname = os.path.splitext(options.private_key.name)[0]
        _private_key = pyhsslms.HssLmsPrivateKey.genkey(keyname, levels=1)

    # Unsupported signature algorithm
    else:
        raise Exception('Unsupported signature algorithm')

    return 0
