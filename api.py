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
import ldap.modlist as modlist

import copy
from base64 import urlsafe_b64encode, b64encode
from random import randint
from datetime import datetime, timedelta
from flask import Flask, url_for, request, Response, json

from xdomain import crossdomain
from ssha import ssha

app = Flask(__name__)

def validate_login(form):

    print "validate_login: %s" % form

    try:
        username = form['username']
        password = form['password']
        if len(username)==0:
            return response({'error': 'Invalid credentials'} ,status=401)
    except KeyError, error:
        print "KeyError %s" % form
        return Response('Wrong request' ,status=400)
    except:

        raise


    user_dn = "uid=%s,ou=Users,ou=auth,dc=guifibages,dc=net" % username
    l = ldap_bind(user_dn, password)
    return (user_dn, l, username, password)

def add_record(l,dn, new):
    try:
        ldif = modlist.addModlist(new)
        l.add_s(dn, ldif)
        return (True, None)
    except ldap.INSUFFICIENT_ACCESS:
        error = {"code": 401, "error": "Insufficient access", "action": new}
        return (False, error)
    except:
        raise
        return False

def increase_current_uidnumber(l):
    update_dn = "uid=template.user,ou=Users,ou=auth,dc=guifibages,dc=net"
    original_record = l.search_s(update_dn, ldap.SCOPE_BASE)[0][1]
    modified_record = copy.deepcopy(original_record)
    modified_record['uidNumber'][0] = str(int(modified_record['uidNumber'][0])+1)
    modified, error = modify_ldap_property(l, update_dn, original_record, modified_record)
    if modified:
        print "increase_current_uidnumber correct"
        return True
    else:
        print "couldn't increase_current_uidnumber"
        return False


def modify_ldap_property(l, modified_dn, old, new):
    try:
        ldif = modlist.modifyModlist(old, new)
        l.modify_s(modified_dn, ldif)
        return (True, None)
    except ldap.INSUFFICIENT_ACCESS:
        error = {"code": 401, "error": "Insufficient access", "action": new}
        return (False, error)
    except:
        raise
        return False

def ldap_bind(binddn, password):
    l = ldap.initialize("ldaps://aaa.guifibages.net:636")
    l.simple_bind_s(binddn, password)
    return l
    """
    try:
        l = ldap.initialize("ldaps://aaa.guifibages.net:636")
        l.simple_bind_s(binddn,password)
        return l
    except ldap.INVALID_CREDENTIALS:
        return response({'error': 'Invalid credentials'} ,status=401)
    except ldap.SERVER_DOWN:
        return response({'error': "Can't connect to server"} ,status=500)
    except ldap.LDAPError, error_message:
        print "Excepcion: %s" % error_message
        return response({'error': "LDAPError: %s" % error_message} ,status=500)
    """


def generate_otp():
    """Return a 6 digits random One Time Password"""
    return "%06d" % randint(1,999999)

def read_pac(view="internet"):
    """Read the specified pac file from disk and return it as a string

    Arguments:
    view -- the intended view (default: "internet")
    """
    try:
        with open('static/%s-pac.js' % view,'r') as pac_file:
            return pac_file.read()
    except IOError, e:
        if e.errno == 2:
            return


# We use this as an argument to json.dumps to convert datetime objects to json
dthandler = lambda obj: obj.isoformat() if isinstance(obj, datetime) else None

def user_access(l, user_dn):
    result = l.search_s(user_dn, ldap.SCOPE_SUBTREE, 'objectClass=*', ['memberOf'])[0][1]
    print "user_access:\n\t%s\n\t%s" % (user_dn, result)
    if 'memberOf' in result and "cn=ldapAdmin,ou=Groups,ou=auth,dc=guifibages,dc=net" in result['memberOf']:
        return "admin"
    else:
        return "user"

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
@crossdomain('*')
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
@crossdomain('*')
def user_info(username):
    global sessions
    user_dn, l, username, password = validate_login(request.form)

@app.route('/api/users', methods = ['POST'])
@crossdomain('*')
def list_users():
    try:
        user_dn, l, username, password = validate_login(request.form)
    except ldap.INVALID_CREDENTIALS:
        return response({'error': 'Invalid credentials'} ,status=401)
    except ldap.SERVER_DOWN:
        return response({'error': "Can't connect to server"} ,status=500)
    except:
        return response({'error': "shit happened"}, 500)
    try:
        result = l.search_s("ou=Users,ou=auth,dc=guifibages,dc=net", ldap.SCOPE_SUBTREE, 'objectClass=person', ['uid', 'cn', 'uidNumber'])
    except ldap.NO_SUCH_OBJECT:
        return response({'error': 'Unauthorized'} ,status=401)
    
    return response(result)

@app.route('/api/user/<target_user>/get', methods = ['POST'])
@crossdomain('*')
def get_user(target_user):

    try:
        user_dn, l, username, password = validate_login(request.form)
    except ldap.INVALID_CREDENTIALS:
        return response({'error': 'Invalid credentials'} ,status=401)
    except ldap.SERVER_DOWN:
        return response({'error': "Can't connect to server"} ,status=500)
    except:
        return response({'error': "shit happened"}, 500)


    target_dn = "uid=%s,ou=Users,ou=auth,dc=guifibages,dc=net" % target_user

    try:
        result = l.search_s(target_dn, ldap.SCOPE_SUBTREE, 'objectClass=*')[0][1]
    except ldap.NO_SUCH_OBJECT:
        return response({'error': 'Not found'} ,status=404)


    result['access_level'] = user_access(l, user_dn)

    return response(result)

@app.route('/api/user/new', methods = ['POST'])
@crossdomain('*')
def add_user():
    result = {}
    try:
        user_dn, l, username, password = validate_login(request.form)
    except ldap.INVALID_CREDENTIALS:
        return response({'error': 'Invalid credentials'} ,status=401)
    except ldap.SERVER_DOWN:
        return response({'error': "Can't connect to server"} ,status=500)
    except:
        return response({'error': "shit happened"}, 500)
    update_dn = "uid=template.user,ou=Users,ou=auth,dc=guifibages,dc=net"
    original_record = l.search_s(update_dn, ldap.SCOPE_BASE)[0][1]
    modified_record = copy.deepcopy(original_record)
    print request.form
    check_search = '(uid=%s)' % request.form['newuser_uid']
    print "add_user -1"
    check = l.search_s("ou=Users,ou=auth,dc=guifibages,dc=net", ldap.SCOPE_SUBTREE, check_search, ['uid', 'cn', 'uidNumber'])
    print "add_user"
    print "add_user: %s (%d)" % (check, len(check))
    if len(check) > 0:

        return  response("User already exists %s" % request.form['newuser_uid'], 409)


    for field in request.form:
        if field in ['username', 'password']:
            continue
        new_value = request.form[field]
        new_value = new_value.encode('utf-8')
        if field == 'userPassword':
            new_value = ssha(request.form[field])
        if field[0:8] == 'newuser_':
            modified_record[field[8:]] = new_value
            continue
        if field not in original_record or original_record[field] != new_value and new_value not in original_record[field]:
            modified_record[field] = new_value
    modified_record['homeDirectory'] = "/guifibages/users/%s" % modified_record['uid']

    print "Minga longa %s" % modified_record

    new_dn = "uid=%s,ou=Users,ou=auth,dc=guifibages,dc=net" % modified_record['uid']
    modified, error = add_record(l, new_dn, modified_record)
    print "Result:\n modified: %s\n error: %s" % (modified, error)
    if modified:
        increase_current_uidnumber(l)
        return response(modified_record)
    else:
        return response(error, error['code'])


@app.route('/api/user/<target_user>/update', methods = ['POST'])
@crossdomain('*')
def update_user(target_user):
    print "update_user:\n\t%s" % request.form
    result = {}
    try:
        user_dn, l, username, password = validate_login(request.form)
    except ldap.INVALID_CREDENTIALS:
        return response({'error': 'Invalid credentials'} ,status=401)
    except ldap.SERVER_DOWN:
        return response({'error': "Can't connect to server"} ,status=500)
    except:
        return response({'error': "shit happened"}, 500)

    update_dn = "uid=%s,ou=Users,ou=auth,dc=guifibages,dc=net" % target_user
    original_record = l.search_s(update_dn, ldap.SCOPE_BASE)[0][1]
    modified_record = copy.deepcopy(original_record)

    for field in request.form:
        if field in ['username', 'password']:
            continue
        new_value = request.form[field]
        new_value = new_value.encode('utf-8')
    	if field == 'userPassword':
    	    new_value = ssha(request.form[field])
        if field not in original_record or original_record[field] != new_value and new_value not in original_record[field]:
            modified_record[field] = new_value

    if original_record == modified_record:
        return response("No changes")

    result['original_record'] = original_record
    result['modified_record'] = modified_record
    modified, error = modify_ldap_property(l, update_dn, original_record, modified_record)
    if modified:
        return response(result)
    else:
        return response(error, error['code'])

@app.route('/api/login', methods = ['POST'])
@crossdomain('*')
def login():
    global sessions
    result = {}
    try:
        user_dn, l, username, password = validate_login(request.form)
    except ldap.INVALID_CREDENTIALS:
        return response({'error': 'Invalid credentials'} ,status=401)
    except ldap.SERVER_DOWN:
        return response({'error': "Can't connect to server"} ,status=500)
    except:
        return response({'error': "shit happened"}, 500)

    ip = get_request_ip(request)
    
    if not username in sessions:
            sessions[username] = {}
    result['access_level'] = user_access(l, user_dn)
    result['otp'] = generate_otp()
    result['ts'] = datetime.now()
    sessions[username][ip] = result
    # We add the pac after saving the result to the session
    if ip[0:3] != '10.':
        result['pac'] = read_pac('internet')
    return response(result)

if __name__ == "__main__":
    global sessions
    sessions = dict()
    app.run(debug=True, port=8060, host="0.0.0.0")
