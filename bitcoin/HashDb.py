import sqlite3,MySQLdb

count = 0

dbms = 'mysql'
database = 'hashes'
user = 'hashes'
password = 'hashes'
table = 'hashes'
server = '127.0.0.1'
debug = False

def hexify (s, flip=False):
    if flip:
        return s[::-1].encode ('hex')
    else:
        return s.encode ('hex')

def unhexify (s, flip=False):
    if flip:
        return s.decode ('hex')[::-1]
    else:
        return s.decode ('hex')

def inttohexstr(i):
	tmpstr = "%s" % hex(i)
	hexstr = tmpstr.replace('0x','').replace('L','')
	return hexstr


def get_der_field(i,binary):
        if (ord(binary[i]) == 02):
                length = binary[i+1]
                end = i + ord(length) + 2
                string = binary[i+2:end]
                return string
        else:
                return None

def hex_der_decode(hexstring):
        binary = unhexify(hexstring)
        full_length = ord(binary[1])
	#print full_length
        if ((full_length + 2) <= len(binary)):
                r = get_der_field(2,binary)
                s = get_der_field(len(r)+4,binary)
                return r,s
        else:
                return None

def hexpadded(i):
	s = hex(i).replace('0x','').replace('L','')
	if ((len(s) % 2) == 1):
		s = "0%s" % s
	return s


def sanitice(b):
	if ord(b[0:1]) == 0:
		return b[1:]
	else:
		return b

class db:
	def __init__(self,pool=2000):
		self.initdb(pool)

	def initdb(self,pool):
		#import sqlite3
		self.pool = pool
		self.table = table
		self.db = database
		self.db_user = user
		self.db_password = password
		self.db_server = server
		self.debug = debug
		if dbms == 'slqlite':
			self.conn = sqlite3.connect(self.db)
		else:
			self.conn = MySQLdb.connect(self.db_server, self.db_user, self.db_password, self.db)

		if self.debug:
			print "db.__init__()"
		self.count = 0
		self.max_count = pool
		self.c = self.conn.cursor()
		self.c.connection.autocommit(True)
		#self.c.execute('BEGIN TRANSACTION;')
		
		self.stat_count = 0
                self.stat_insert = 0
                self.stat_dup = 0
		self.stat_max = 1000

 	def db_close(self):
                self.conn.commit()
                self.conn.close()

	def __del__(self):
		self.db_close()

	def store(self,txhash,sig,hash):

		self.count = self.count + 1
        	r,s = hex_der_decode(sig.encode('hex'))
	
		str_r = sanitice(r).encode('hex')
		str_s = sanitice(s).encode('hex')
	
		#strtxhash =  (hex(txhash).replace("0x","").replace("L",""))
		strhash = hexpadded(hash).decode('hex')[::-1].encode('hex')

		sql = "INSERT INTO %s VALUES ('%064x','%s','%s','%s')" % (self.table,txhash,str_r,str_s,strhash)
		self.stat_count = self.stat_count + 1 
		if self.debug:
			print sql

		try:
			self.c.execute(sql)
			self.stat_insert = self.stat_insert + 1

		except MySQLdb.IntegrityError, e:
			self.stat_dup = self.stat_dup + 1 
			pass		

		except MySQLdb.OperationalError,e:
			if e[0] == 2013:
				print "Connection lost, reconecting..."
				self.initdb(self.pool)
				self.store(txhash,hash.sig)		

		if (self.stat_count == self.stat_max):
			print "Stats count %d, inserted %d, dups %d" % (self.stat_count,self.stat_insert,self.stat_dup)
			self.stat_count = 0
			self.stat_insert = 0
			self.stat_dup = 0
		
		if (self.count == self.max_count):
			#self.c.execute("COMMIT;")
			#self.c.execute("BEGIN TRANSACTION;")
			self.conn.commit()
			self.count = 0
			print "Flushed %s..." % self.db_file


def test():

	der1='304502202e434e9c5784748131e4576a0441d96ee102e8bf8e922a0fc636d98a75ba0ec6022100d490cb44864407ef7f1ceb6ce901f65b50f84569d6f08861ee31a6c5896445c501'
	der2='304402202e434e9c5784748131e4576a0441d96ee102e8bf8e922a0fc636d98a75ba0ec602205c802925ee76a2c8396c7eab85c70c3d0b80f69e0cc938876b8bdc378a8dda0001'	
	r,s = hex_der_decode(der1)
	r = sanitice(r)
	s = sanitice(s)
	print r.encode('hex'),s.encode('hex')
	r,s = hex_der_decode(der2)
	print r.encode('hex'),s.encode('hex')

#test()
