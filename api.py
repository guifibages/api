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
import os
import re

from bs4 import BeautifulSoup
from flask import Flask, jsonify, request
import requests

import bot

app = Flask(__name__)


@app.route('/ping/<ip>')
@app.route('/ping/<ip>/<count>')
def pinghandler(ip, count=2):
    return jsonify(ping(ip, count))


@app.route('/traceroute/<ip>')
def traceroutehandler(ip):
    return jsonify(traceroute(ip))


@app.route('/whois/<ip>')
def ipinfohandler(ip):
    info = whois(ip)
    return jsonify(info)


def whois(ip):
    print("whoising: " + ip)
    host = requests.get('http://guifi.net/ca/guifi/menu/ip/ipsearch/{}'.
                        format(ip))
    s = BeautifulSoup(host.text)
    h = s.find("th", text="nipv4").find_parent("table").find_all("td")
    if len(h) == 0:
        return dict(status=-1, ip=ip, text="Not found")
    node = "{} (http://guifi.net{})".format(h[5].a.text, h[5].a["href"])
    status = 0
    return dict(status=status, ip=ip, text="Node: {}".format(node))


def traceroute(ip):
    try:
        address = ipaddress.ip_address(ip)
        command = "traceroute"
        if isinstance(address, ipaddress.IPv6Address):
            command = "traceroute6"
    except ValueError:
        return dict(status=-1, text="Error: Invalid IP address",  ip=ip)

    try:
        text = subprocess.check_output([command, ip],
                                       stderr=subprocess.STDOUT,
                                       universal_newlines=True)
        status = 0
    except subprocess.CalledProcessError as e:
        text = e.output
        status = e.returncode
    except Exception as e:
        text = e
        status = -1
    return dict(status=status, ip=ip, text=text)


def ping(ip, count=2):
    try:
        address = ipaddress.ip_address(ip)
        command = "ping"
        if isinstance(address, ipaddress.IPv6Address):
            command = "ping6"
    except ValueError:
        return dict(status=-1, text="Error: Invalid IP address", ip=ip)

    try:
        text = subprocess.check_output([command, '-c %d' % int(count), ip],
                                       stderr=subprocess.STDOUT,
                                       universal_newlines=True)
        status = 0
    except subprocess.CalledProcessError as e:
        text = e.output
        status = e.returncode
    except Exception as e:
        text = e
        status = -1
    return dict(status=status, ip=ip, text=parse_ping(text))


def parse_ping(text):
    match = re.search("\s(?P<packets>\d+)\spackets\stransmitted,"
                      "\s(?P<received>\d+)\spackets\sreceived,\s"
                      "(?P<loss>\d+%)\spacket\sloss", text, re.MULTILINE)
    if match is None:
        return text
    return match.groupdict()


@app.route('/telegram', methods=['POST'])
def telegramWebHook():
    bot.Message(request.json)
    return ""


if __name__ == "__main__":
    bot.token = os.environ['TELEGRAM_TOKEN']
    bot.app = app
    client = requests.Session()
    app.run(debug=True, port=8060, host="0.0.0.0")
