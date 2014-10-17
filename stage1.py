#!/usr/bin/python
#
# testscript.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import struct
import string
import os
import sys
import time
import Log
import MemPool
import ChainDb
import cStringIO
import leveldb

from bitcoin.serialize import *
from bitcoin.core import *
from bitcoin.coredefs import NETWORKS
from bitcoin.core import CBlock
from bitcoin.serialize import ser_uint256
from bitcoin.scripteval import VerifySignature

from optparse import OptionParser

NET_SETTINGS = {
	'mainnet' : {
		'log' : '/home/dclavijo/chaindb/testscript.log',
		'db' : '/home/dclavijo/chaindb'
	},
	'testnet3' : {
		'log' : '/spare/tmp/testtestscript.log',
		'db' : '/spare/tmp/chaintest'
	}
}

MY_NETWORK = 'mainnet'
SETTINGS = NET_SETTINGS[MY_NETWORK]
log = Log.Log(SETTINGS['log'])
mempool = MemPool.MemPool(log)

SKIP_TX = []

msg_start = "f9beb4d9".decode('hex')

#def loadfile(filename,skip_load_height,skip_scan_height,chaindb):
def loadfile(filename,start,end,chaindb):
	fd = os.open(filename, os.O_RDONLY)
	#self.log.write("IMPORTING DATA FROM " + filename)
	buf = ''
	wanted = 4096

	count = 1

	while True:
		if wanted > 0:
			if wanted < 4096:
				wanted = 4096
			s = os.read(fd, wanted)
			if len(s) == 0:
				break

			buf += s
			wanted = 0

		buflen = len(buf)
		startpos = string.find(buf, msg_start)
		if startpos < 0:
			wanted = 8
			continue

		sizepos = startpos + 4
		blkpos = startpos + 8
		if blkpos > buflen:
			wanted = 8
			continue

		blksize = struct.unpack("<i", buf[sizepos:blkpos])[0]
		if (blkpos + blksize) > buflen:
			wanted = 8 + blksize
			continue

		ser_blk = buf[blkpos:blkpos+blksize]
		buf = buf[blkpos+blksize:]

		f = cStringIO.StringIO(ser_blk)
		block = CBlock()
		block.deserialize(f)

		count += 1

		skip_load = (count < start)
		if skip_load:
			if ((count % 10000) == 0):
				print "skiping: %d" % count
			continue

		if (count >= end):
			print "Exit!"
			sys.exit(0)	

		ret = chaindb.putblock(block)

		height = chaindb.getheight()

		#if count == 778:
		#	print repr(block)

		heightidx = ChainDb.HeightIdx()
                heightidx.deserialize(chaindb.height(str(height)))
                blkhash = heightidx.blocks[0]



		skiped = False
		scanned = False
		
		#skip_scan = (height < skip_scan_height)	
		#if not skip_scan:
		#	if ret:
		#		scanned = scan_vtx(chaindb,block)
		
		strBlkHash = hex(blkhash).replace('0x','').replace('L','')
		print "Count: %d Putblock: %s Height: %d BlockHash: %s" % (count,ret,height,strBlkHash)

	print "tell: %d" % fd.tell()
	return count
		
def scan_vtx(chaindb,ser_block):
	scanned_tx = 0
	failures = 0
	#print ser_block
	for tx_tmp in ser_block.vtx:
		if tx_tmp.is_coinbase():
                	continue
             	scanned_tx += 1
               	if not scan_tx(chaindb,tx_tmp):
          		failures += 1
                	sys.exit(1)
	print "scanned_tx %d" % scanned_tx
	return True


def chaindb_init():
	chaindb = ChainDb.ChainDb(SETTINGS,SETTINGS['db'], log, mempool,
			  NETWORKS[MY_NETWORK], True)
	chaindb.blk_cache.max = 1000
	return chaindb

def scan_tx(chaindb,tx):
	tx.calc_sha256()

	if tx.sha256 in SKIP_TX:
		return True
	
	#print tx	

	for i in xrange(len(tx.vin)):
		txin = tx.vin[i]
		txfrom = chaindb.gettx(txin.prevout.hash)
		if txfrom:
			if not VerifySignature(txfrom, tx, i, 0):
				log.write("TX %064x/%d failed" % (tx.sha256, i))
				log.write("FROMTX %064x" % (txfrom.sha256,))
				log.write(txfrom.__repr__())
				log.write("TOTX %064x" % (tx.sha256,))
				log.write(tx.__repr__())
				return False
	return True


def delete_blocks(chaindb,start,end):
	batch = leveldb.WriteBatch()
	for height in xrange(start,end):
		heightidx = ChainDb.HeightIdx()
                heightidx.deserialize(chaindb.height(str(height)))

                blkhash = heightidx.blocks[0]
		strBlkHash = hex(blkhash).replace('0x','').replace('L','')
		ser_hash = ser_uint256(blkhash)
		
		batch.Delete('blocks:'+ser_hash)
		batch.Delete('height:'+str(height))
		print "deleted: %064x %d" % (blkhash,height)

	print start
	batch.Put('misc:height:',str(start-1))
	chaindb.db.Write(batch)


def single_delete(chaindb,height):
	batch = leveldb.WriteBatch()
	heightidx = ChainDb.HeightIdx()
        heightidx.deserialize(chaindb.height(str(height)))

	blkhash = heightidx.blocks[0]
        strBlkHash = hex(blkhash).replace('0x','').replace('L','')
        ser_hash = ser_uint256(blkhash)

        batch.Delete('blocks:'+ser_hash)
        batch.Delete('height:'+str(height))
	chaindb.db.Write(batch)
	

def scan_block_range(chaindb,start_height,end_height):
	scanned = 0

	failures = 0

	if end_height > start_height:
		arg3 = 1
	else:
                arg3 = -1
	
	for height in xrange(start_height,end_height,arg3):
		heightidx = ChainDb.HeightIdx()
		heightidx.deserialize(chaindb.height(str(height)))

		blkhash = heightidx.blocks[0]
		print "blockHash: %064x" % blkhash
		ser_block = chaindb.getblock(blkhash)
		scanned_tx = 0
		if ser_block:
			for tx_tmp in ser_block.vtx:
				if tx_tmp.is_coinbase():
					continue
				scanned_tx += 1
				if not scan_tx(chaindb,tx_tmp):
					failures += 1
					#sys.exit(1)
				#print "scanned_tx: %d failures: %d" % (scanned_tx,failures)
		else:
			print "Error: No data"
		print "Height: %d of %d, txs: %d" % (height,end_height,scanned_tx)
		
		scanned += 1

def repack(a):
        return "".join(reversed([a[i:i+2] for i in range(0, len(a), 2)]))

def settopheight(chaindb,height,hash):
        batch = leveldb.WriteBatch()
        batch.Put('misc:height', str(height))
        batch.Put('misc:total_work', hex(0L))

        ser_hash = repack(hash).decode('hex')
        batch.Put('misc:tophash', ser_hash)
        chaindb.db.Write(batch)

def setheight(chaindb,height,hash):
        batch = leveldb.WriteBatch()
        batch.Put('height:'+str(height),hash)
        chaindb.db.Write(batch)


def resettotalwork(chaindb):
	batch.Put('misc:total_work', hex(0L))
	chaindb.db.Write(batch)

def getheight(chaindb,height):
        try:
                print "height: %d %s" % (height,chaindb.db.Get('height:'+str(height)))
                return True
        except:
                return False

def displayrange(chaindb,start,end):
        errors = False
        for i in xrange(start,end):
                if not getheight(chaindb,i):
                        errors = True
                        #print "Error at height: %d" % i
        if errors:
                print "Errors"


def printtophash(chaindb):
        print "topheight:",chaindb.db.Get('misc:height'), "%064x" % uint256_from_str(chaindb.db.Get('misc:tophash'))

def main():

	parser = OptionParser()
	parser.add_option("-l","--load",dest="load")
	parser.add_option("-f", "--file", dest="blockfile",
                  help="load blockchain from file", metavar="FILE")
	#parser.add_option("-s", "--start", dest="start")
	#parser.add_option("-e", "--end", dest="end")
	parser.add_option("-c","--count", dest="count", help="Count blocks from file")
	parser.add_option("-d","--disconnectblock", dest="disconnect_block", help="disconnects a block")
	parser.add_option("","--settopheight",dest="settopheight")
	parser.add_option("","--setheight",dest="setheight")
	parser.add_option("","--displayrange",dest="displayrange")
	parser.add_option("","--resettotalwork",dest="resettotalwork")

	(options,args) = parser.parse_args()

	chaindb = chaindb_init()

	#if(options.count and options.blockfile <> None):	
	#	count = loadfile(options.blockfile,10000000000000000,options.end,chaindb)
	#	print "COUNT: %d" % count

	if options.resettotalwork:
		resettotalwork(chaindb)

	if options.setheight:
		opts= options.setheight.split()
		setheight(chaindb,opts[0],hex(int(opts[1],16)))

	if options.settopheight:
		opts =  options.settopheight.split()
		settopheight(chaindb,opts[0],opts[1])

	if options.displayrange:
		opts =  options.displayrange.split()
		#print opts[0],opts[1]
                displayrange(chaindb,int(opts[0]),int(opts[1]))
		printtophash(chaindb)

	if(options.disconnect_block):
		try:
			opts = options.disconnect_block.split()
			#heightidx = ChainDb.HeightIdx()
               		#heightidx.deserialize(chaindb.height((opts[0])))
	               	#blkhash = heightidx.blocks[0]
                	#print "blockHash: %s" % blkhash
               		#ser_block = chaindb.getblock(blkhash)
			#chaindb.disconnect_block(ser_block)
			delete_blocks(chaindb,int(opts[0]),int(opts[1]))
		except:
			single_delete(chaindb,options.disconnect_block)
						

	if options.load:
		opts = options.load.split()
		if opts[0] == opts[1]:
			opts[1] = int(opts[1]) + 1
		scan_block_range(chaindb,int(opts[0]),int(opts[1]))

	
				

if __name__ == "__main__":
    main()
