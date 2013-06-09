import base64, getpass, hashlib, os
def ssha(string):
	string = string.encode('utf-8')
	salt = os.urandom(8) # edit the length as you see fit
	print "salt: " + salt
	hash = hashlib.sha1(string + salt)
	dgst = hash.digest()
	print "dgst: " + dgst
	b64 = base64.b64encode(dgst + salt)
	return '{SSHA}' + b64
	#return '{SSHA}' + base64.b64encode(hashlib.sha1(string + salt).digest() + salt)
