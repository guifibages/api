#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Guifibages Telegram Bot
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

import requests

import api


def telegram(action, payload):
    print("telegramming: |{}| {}".format(token, action))
    url = "https://api.telegram.org/bot{}/{}".format(token, action)
    app.logger.debug("url: %s" % url)
    return requests.post(url, data=payload)


class Message:
    def __init__(self, d):
        vars(self).update(d)
        self.chat = self.message['chat']['id']
        self.is_group = "title" in self.message['chat']
        self.commands = ['ping', 'traceroute']
        try:
            self.parse()
        except Exception as e:
            app.logger.error("Cannot parse:\n %s\n %s", self.message, e)

    def parse(self):
        self.text = self.message['text']
        if self.text[0] != "/" or " " not in self.text:
            return
        self.command, self.args = self.text.split(None, 1)
        self.command = self.command[1:].lower()
        try:
            print("Trying", self.command)
            getattr(self, self.command)()
        except Exception as e:
            print("Exception on", self.command, e)
            sendMessage(self.chat,
                        "{0}: command not found".format(self.command))

    def whois(self):
        result = api.whois(self.args)
        print("whois result: {}".format(result))
        msg = "whois {0}\n{1}".format(result['ip'], result['text'])
        sendMessage(self.chat, msg)

    def ping(self):
        result = api.ping(self.args)
        msg = "ping {0}\n{1}".format(result['ip'], result['text'])
        sendMessage(self.chat, msg)

    def traceroute(self):
        self.mtr()

    def mtr(self):
        result = api.traceroute(self.args)
        msg = "traceroute {0}\n{1}".format(result['ip'], result['text'])
        sendMessage(self.chat, msg)


def sendMessage(chat_id, text):
    payload = {'chat_id': chat_id, 'text': text}
    result = telegram('sendMessage', payload)
    app.logger.debug("Answering:\n %s\n%s" % (payload, result.text))


def sendChatAction(chat_id, action):
    payload = {'chat_id': chat_id, 'action': action}
    result = telegram('sendChatAction', payload)
    app.logger.debug("Answering:\n %s\n%s" % (payload, result))
