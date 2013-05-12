import base64, getpass, hashlib, os
def ssha(string):
	salt = os.urandom(8) # edit the length as you see fit
	return '{SSHA}' + base64.b64encode(hashlib.sha1(string + salt).digest() + salt)