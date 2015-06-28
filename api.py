#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Guifibages api provider
#
# Copyright 2015 Associació d'Usuaris Guifibages
# Author: Ignacio Torres Masdeu <i@itorres.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import ipaddress
import re

from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/ping/<ip>')
@app.route('/ping/<ip>/<count>')
@app.route('/ping/<ip>/<count>/<parsed>')
def ping(ip, count = 2, format = "json"):
    try:
        address = ipaddress.ip_address(ip)
        if (isinstance(address, ipaddress.IPv4Address) and
            not address.is_private):
            return jsonify(result=-1, text="Can only ping private IPv4 addresses (%s)" % ip)
    except ValueError:
        return jsonify(result=-1, text="Invalid IP address: %s" % ip)

    try:
        text = subprocess.check_output(['ping', '-c %d' % int(count), ip], universal_newlines=True)
        result = 0
    except subprocess.CalledProcessError as e:
        text = str(e.output)
        result = e.returncode
    except Exception as e:
        text = str(e)
        result =-1
    return jsonify(status=result, ip=ip, result=parse_ping(text))


def parse_ping(text):
    match = re.search("\s(?P<packets>\d+)\spackets\stransmitted,\s(?P<received>\d+)\spackets\sreceived,\s(?P<loss>\d+%)\spacket\sloss", text, re.MULTILINE)
    if match is None:
        return text
    return match.groupdict()


if __name__ == "__main__":
    app.run(debug=True, port=8060, host="0.0.0.0")
