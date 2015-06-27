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

import subprocess

from flask import Flask, request
import requests

app = Flask(__name__)


def getToken():
    if "client" in globals():
        try:
            r = client.get("http://172.17.42.1:4001/v2/keys/guifibages.net/bot/token")
            token = r.json['node']['value']
        except:
            pass
        if "token" not in locals():
            with open("token", "r") as myfile:
                token = myfile.read().strip()
    return token


def telegram(action, payload):
    url = "https://api.telegram.org/bot%s/%s" % (token, action)
    app.logger.debug("url: %s" % url)
    return client.post(url, data=payload)


class Message:
    def __init__(self, d):
        vars(self).update(d)
        self.chat = self.message['chat']['id']
        self.is_group = "title" in self.message['chat']
        self.commands = {'ping': ['ping', '-c 2']}
        try:
            self.parse()
        except:
            app.logger.error("Cannot parse:\n %s", self.message)


    def parse(self):
        if self.is_group:
            self.text = self.message['text'].split(None, 1)[1]
        else:
            self.text = self.message['text']
        if self.text[0] != "/" or " " not in self.text:
            return
        if "client" in globals():
            sendChatAction(self.chat, "typing")
        self.command, self.args = self.text.split(None, 1)
        self.command = self.command[1:].lower()
        if self.command in self.commands:
            cli = self.commands[self.command]
            cli.append(self.args)
            try:
                self.result = subprocess.check_output(cli, )
            except Exception, e:
                self.result = e.output
            if "client" in globals():
                sendMessage(self.chat, self.result)

def sendMessage(chat_id, text):
    payload = {'chat_id': chat_id, 'text': text}
    result = telegram('sendMessage', payload)
    app.logger.debug("Answering:\n %s\n%s" % (payload, result.text))
    

def sendChatAction(chat_id, action):
    payload = {'chat_id': chat_id, 'action': action}
    result = telegram('sendChatAction', payload)
    app.logger.debug("Answering:\n %s\n%s" % (payload, result))


@app.route('/telegram', methods=['POST'])
def telegramWebHook():
    m = Message(request.json)
    return ""

"""
except:
        resp=jsonify({'error': 'Malformed message'})
        resp.status_code = 400
        return resp
"""

if __name__ == "__main__":
    client = requests.Session()
    token = getToken()
    app.run(debug=True, port=8050, host="0.0.0.0")