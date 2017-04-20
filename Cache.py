#
# Cache.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
import gc
import hashlib
import zlib
import cPickle
import sys
import os
import psutil
import io

class Cache(object):
	def __init__(self, max,compress=False):
		self.d = {}
		#self.h = {}
		self.l = []
		self.max = max
		self.reserve = 1000
		self.compress = compress
		gc.enable()
		print "Cache init: %d items, compress: %s" % (max,compress)

	def delete(self,k):
		kdel = self.l[k]
		del self.l[k]
		del self.d[kdel]

	def clean(self,n):
		while (len(self.l) > n):
                	self.delete(0)
		print "Cache cleaned:", n

	def cleanall(self):
		while (len(self.l) > self.reserve):
			self.delete(0)
		print "Cache purged"

	def setnewlimit(self,limit):
		self.cleanall()
		self.max = limit

	def len(self):
		return len(self.l)

	def put(self, k, v):
		if self.compress:
			v = zlib.compress(cPickle.dumps(v),1)

		self.d[k] = v
		self.l.append(k)

		while (len(self.l) > self.max):
			self.delete(0)

	def _dec(self,v):
		try:
			r = cPickle.loads(zlib.decompress(v))
		except:
			r = v
		return r

	def get(self, k):
		try:
			v = self.d[k]
			if self.compress:
				v = self._dec(v)
			return v
		except:
			return None

	def exists(self, k):
		return k in self.d

	def sizedata(self):
		l = 0
		for k in self.d:
			l += sys.getsizeof(self.d[k])
		return l		

	def sizeindex(self):
		l = 0
		for i in xrange(0,len(self.l)-1):
			l += sys.getsizeof(self.l[i])
		return l

	def stat(self):
		l0 = self.sizedata()
		l1 = self.sizeindex()
		print "Cache items: %d of %d, size_data: %d KB, size_index: %d KB, total: %d KB" % (len(self.l),self.max,(l0//1024),(l1//1024),((l0+l1)//1024)) 


def sha256(s):
	h = hashlib.sha256(s)
	return h.hexdigest()


def getmemory():
        process = psutil.Process(os.getpid())
        return (process.memory_info().rss // (1024**2))

def memorystat():
        used = getmemory()
        print "Memory Used: %d MB" % used
        return used


if __name__ == "__main__":
	c = Cache(60000,compress=False)
	fp =  io.BufferedReader(io.FileIO('/dev/urandom','rb'))
	for i in xrange(0,1200):
		data = fp.read(1024**2)
		h = sha256(data)
		c.put(h,data)
		h2 = sha256(c.get(h))
		print h,h2
		if i % 1000 ==0:
			print i
	c.stat()
	memorystat()
