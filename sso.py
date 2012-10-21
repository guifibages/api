#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Guifibages sso provider
#
# Copyright 2012 Associació d'Usuaris Guifibages
# Author: Ignacio Torres Masdeu <ignacio@xin.cat>
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



import ldap
from base64 import urlsafe_b64encode
from os import urandom
from datetime import datetime, timedelta
from flask import Flask, url_for, request, Response, json
app = Flask(__name__)

def generate_otp():
    return urlsafe_b64encode(urandom(20))

dthandler = lambda obj: obj.isoformat() if isinstance(obj, datetime) else None
def response(msg, status=200):
    return Response(json.dumps(msg, default=dthandler), status=status)

def get_request_ip(request):
    if not request.headers.getlist("X-Forwarded-For"):
       ip = request.remote_addr
    else:
       ip = request.headers.getlist("X-Forwarded-For")[0]
    return ip

def is_trusted_server(ip):
    servers = ['10.228.17.24', '10.228.17.29']
    return ip in servers

@app.route('/api/user/<username>/otp', methods = ['POST'])
def validate_otp(username):
    if not 'password' in request.form or not 'ip' in request.form:
        return response({'error': 'Invalid credentials'} ,status=401)
    password = request.form['password']
    ip = request.form['ip']

    if not ip in sessions[username]:
        return response({'error': 'Invalid IP'} ,status=401)
    if password != sessions[username][ip]['otp']:
        return response({'error': 'Invalid credentials'} ,status=401)
    return response(True)


@app.route('/api/user/<username>', methods = ['GET'])
def user_info(username):
        global sessions
        if username in sessions:
                print "Seguimos get"
                ret = {}
                for ip, value in sessions[username].items():
                        timestamp = value['ts']
                        if datetime.now()-timestamp < timedelta(seconds=30):
                            if is_trusted_server(get_request_ip(request)):
                                ret[ip] = value
                            else:
                                ret[ip] = True
                return response(ret)
        else:
            return response({'error': 'Not found'} ,status=404)

@app.route('/api/login', methods = ['POST'])
def login():
        global sessions
        result = {}
        try:
            username = request.form['username']
            password = request.form['password']
            if len(username)==0:
                return response({'error': 'Invalid credentials'} ,status=401)
        except KeyError, error:
            print "KeyError %s" % request.form
            return Response('Wrong request' ,status=400)
        user_dn = "uid=%s,ou=Users,ou=auth,dc=guifibages,dc=net" % username
        try:
                l = ldap.initialize("ldaps://aaa.guifibages.net:636")
                l.simple_bind_s(user_dn,password)
        except ldap.INVALID_CREDENTIALS:
                return response({'error': 'Invalid credentials'} ,status=401)
        except ldap.SERVER_DOWN:
                return response({'error': "Can't connect to server"} ,status=500)
        except ldap.LDAPError, error_message:
                print "Excepcion: %s" % error_message
                return response({'error': "LDAPError: %s" % error_message} ,status=500)

        ip = get_request_ip(request)

        if not username in sessions:
                sessions[username] = {}
        result['otp'] = generate_otp()
        result['ts'] = datetime.now()
        sessions[username][ip] = result
        # We add the pac after saving the result to the session
        if ip[0:3] != '10.':
            with open('pac.js','r') as pac_file:
                result['pac'] = pac_file.read()
        return response(result)

if __name__ == "__main__":
        global sessions
        sessions = dict()
        app.run(debug=True)
