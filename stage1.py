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

import threading

from bitcoin.serialize import *
from bitcoin.core import *
from bitcoin.coredefs import NETWORKS
from bitcoin.core import CBlock
from bitcoin.serialize import ser_uint256
from bitcoin.scripteval import VerifySignature,hashDB
from bitcoin.messages import *

from optparse import OptionParser

maxthreads = 8

timer_continue = True

recovery = {}

fp_recovery = False
fp_recovery_fname = ""
#fp_recovery_fname = "/media/vdc1/dclavijo/chaindb/recovery.tmp"



timer = False

runs_exit = 0

def write_recovery():

	global recovery

	log.write("Recovery info: %s" % str(recovery))

	global fp_recovery
	global fp_recovery_name

	#print fp_recovery,fp_recovery_fname

	if fp_recovery:
		fp_recovery.truncate(0)
		fp_recovery.seek(0)
		fp_recovery.write(str(recovery) + "\n")

	else:
		fp_recovery = open(fp_recovery_fname,"w")
		fp_recovery.truncate(0)
		fp_recovery.seek(0)
		fp_recovery.write(str(recovery) + "\n")

	if fp_recovery:
		fp_recovery.flush()	

	
def dostat():

                stat_max = 60

                stat_count = 0
                stat_insert = 0
                stat_dup = 0
		stat_error = 0

                for DB in hashDB:

                        stat_count = stat_count + hashDB[DB].stat_count
                        stat_insert = stat_insert + hashDB[DB].stat_insert
                        stat_dup = stat_dup + hashDB[DB].stat_dup
			stat_error = stat_error + hashDB[DB].stat_error

                #sys.exit(0)

		
		thread_count = len(threads)

                print "Threads: (%d, %d), Stats: (count %d, inserted %d, dups %d, error %d) per %d sec" % (threading.active_count(),thread_count,stat_count,stat_insert,stat_dup,stat_error,stat_max)

		#text = ""
		#global recovery
		#for k, v in recovery.iteritems():
		#	text = text + str(k) + " " + str(v)

		write_recovery()

		#recovery = list()
		

                for DB in hashDB:
                        hashDB[DB].stat_count = 0
                        hashDB[DB].stat_insert = 0
                        hashDB[DB].stat_dup = 0
			hashDB[DB].stat_error = 0

	
		if (thread_count > 0):
			global timer
			timer = False
               		timer = threading.Timer(stat_max,dostat)
                	timer.start()
	
		global runs_exit	
		if stat_count == 0:
			runs_exit = runs_exit + 1
		else:
			runs_exit = 0
		if runs_exit == 5:
			print "Exiting due runout..."
			#sys.exit(0) 
			os.execve('killall stage1.py')
			#os.kill()

NET_SETTINGS = {
	'mainnet' : {
		'log' : '/media/vdc1/dclavijo/chaindb/testscript.log',
		'db' : '/media/vdc1/dclavijo/chaindb'
	},
	'testnet3' : {
		'log' : '/tmp/testtestscript.log',
		'db' : '/tmp/chaintest'
	}
}

MY_NETWORK = 'mainnet'
SETTINGS = NET_SETTINGS[MY_NETWORK]
log = Log.Log(SETTINGS['log'])
#mempool = MemPool.MemPool(log)

SKIP_TX = []

msg_start = "f9beb4d9".decode('hex')

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

		if (end > -1) and (count >= end):
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
                	#sys.exit(1)
	print "scanned_tx %d" % scanned_tx
	return True


def chaindb_init():
	chaindb = ChainDb.ChainDb(SETTINGS,SETTINGS['db'], log, "",
			  NETWORKS[MY_NETWORK], True)
	chaindb.blk_cache.max = 1000
	return chaindb

def scan_tx(chaindb,tx):
	tx.calc_sha256()

	flag = 1
	
	for i in xrange(len(tx.vin)):
		txin = tx.vin[i]
		try:
			txfrom = chaindb.gettx(txin.prevout.hash)
		except:
			txfrom = ""
			log.write("ERROR: tx %064x" % tx.sha256)
			
		if txfrom:
			if not VerifySignature(txfrom, tx, i, 0):
				log.write("TX %064x/%d failed" % (tx.sha256, i))
				#log.write("FROMTX %064x" % (txfrom.sha256,))	
				#log.write(txfrom.__repr__())
				#log.write("TOTX %064x" % (tx.sha256,))
				#log.write(tx.__repr__())
				flag = 0

	return flag


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
	
def verify_blocks(chaindb,start_height,end_height):

	for height in xrange(start_height,end_height):
        	heightidx = ChainDb.HeightIdx()
           	heightidx.deserialize(chaindb.height(str(height)))

                blkhash = heightidx.blocks[0]
                print threading.currentThread().getName(),"height: %d of %d blockHash: %064x" % (height,end_height,blkhash)
                ser_block = chaindb.getblock(blkhash)


def scan_block_range(chaindb,start_height,end_height,arg3):
	scanned = 0

	failures = 0

	#if end_height > start_height:
	#	arg3 = 1
	#else:
        #       arg3 = -1
	
	for height in xrange(start_height,end_height,arg3):

		recovery[threading.currentThread().getName()] = (start_height,height,end_height)

		heightidx = ChainDb.HeightIdx()
		heightidx.deserialize(chaindb.height(str(height)))

		blkhash = heightidx.blocks[0]
		print "[" + threading.currentThread().getName() + "] Height: %d of %d, blockHash: %064x" % (height,end_height,blkhash)

		try:
			ser_block = chaindb.getblock(blkhash)
		except:
			ser_block = ""
			log.write("Error deserializing block at height %d blockhash: %064x" % (height,blkhash))

		scanned_tx = 0
		if ser_block:
			for tx_tmp in ser_block.vtx:
				if tx_tmp.is_coinbase():
					continue
				scanned_tx += 1
				if scan_tx(chaindb,tx_tmp) < 1:
					if scan_tx(chaindb,tx_tmp) < 1:
						#print "Error!!!"
						failures += 1
		else:
			print "Error: No data"
		#print threading.currentThread().getName(),"Done Height: %d of %d, txs: %d" % (height,end_height,scanned_tx)
		
		scanned += 1

	log.write("End Height: %d %d %d" % (start_height,height,end_height))
	

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

threads = list()

def newthread(target,args):
	t = threading.Thread(target=target,args=args)
    	threads.append(t)
    	t.start()
	#print threading.currentThread().getName(),"Started"


def proc_json(json_data,chaindb):
	json_data = json_data.replace('\r','').replace('\n','')
	import ast
       	j = ast.literal_eval(json_data)
	maxthreads = len(j)
	for m in j:
        	Start = j[m][1]
        	End = j[m][2]
        	newthread(target=scan_block_range,args=(chaindb,Start,End,maxthreads))
                

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
	parser.add_option("","--verifyblocks",dest="verifyblocks")
	parser.add_option("","--json",dest="json")
	parser.add_option("","--recovery",dest="recovery")

	(options,args) = parser.parse_args()

	chaindb = chaindb_init()

	if(options.count and options.blockfile <> None):	
		count = loadfile(options.blockfile,1,-1,chaindb)
		print "COUNT: %d" % count

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

	if options.verifyblocks:
		opts =  options.verifyblocks.split()
		verify_blocks(chaindb,int(opts[0]),int(opts[1]))

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
						
	if options.json:
		proc_json(options.json,chaindb)	
		dostat()

	if options.recovery:
		global fp_recovery_fname
		fp_recovery_fname = options.recovery
		fp_recovery = open(options.recovery,'r')
		json_data = fp_recovery.readline()
		fp_recovery.close()

		proc_json(json_data,chaindb)

		dostat()

	if options.load:
		opts = options.load.split()
		if opts[0] == opts[1]:
			opts[1] = int(opts[1]) + 1

		#scan_block_range(chaindb,int(opts[0]),int(opts[1]))

		for i in xrange(1,maxthreads+1):
			Start = int(opts[0])
			End = int(opts[1]) 
			delta = (End - Start) / maxthreads
			newthread(target=scan_block_range,args=(chaindb,Start+i,End,maxthreads))
			#newthread(target=scan_block_range,args=(chaindb,Start + (delta * (i-1)),Start + (delta * i),))
					
		dostat()
		#timer_continue = False

if __name__ == "__main__":
    main()
