#!/usr/bin/python
#
# testscript.py

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
from bitcoin.scripteval import VerifySignature

from optparse import OptionParser

#fp = open('/tmp/hexfilter','a')

NET_SETTINGS = {
	'mainnet' : {
		'log' : '/media/vdb1/dclavijo/chaindb/addrscript.log',
		'db' : '/media/vdb1/dclavijo/chaindb'
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


def chaindb_init():
	chaindb = ChainDb.ChainDb(SETTINGS,SETTINGS['db'], log, "",
			  NETWORKS[MY_NETWORK], True)
	chaindb.blk_cache.max = 1000
	return chaindb

def scan_tx(chaindb,tx,height):
	tx.calc_sha256()
	found = True
	if found == True:
		for i in xrange(len(tx.vin)):
			txin = tx.vin[i]
			script = CScript(txin.scriptSig)
        		while script.pc < script.pend:
                		if not script.getop():
                        		return False
                		sop = script.sop
				#print sop.op, sop.data.encode('hex')
				if sop.op > 33 and sop.op < 75:
					if ord(sop.data[0]) == 48:
						hashtype = sop.data[-1:]
						if (ord(hashtype) & 31) == 2:
							hashtypestr = "SIGHASH_NONE"
							print "%064x %s %d" % (tx.sha256, hashtypestr,height)
							
						if (ord(hashtype) & 31) == 3:
							hashtypestr = "SIGHASH_SINGLE"
							print "%064x %s %d" % (tx.sha256, hashtypestr,height)
							
						if ord(hashtype) == 128:
							hashtypestr = "SIGHASH_ANYONE"
							print "%064x %s %d" % (tx.sha256, hashtypestr,height)
	#sys.stdout.flush()
							
				
			
def scan_block_range(chaindb,start_height,end_height,arg3=1):
	scanned = 0

	failures = 0

	for height in xrange(start_height,end_height,arg3):
		log.write("Height: %s" % str(height))

		heightidx = ChainDb.HeightIdx()
		heightidx.deserialize(chaindb.height(str(height)))

		blkhash = heightidx.blocks[0]
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
				if scan_tx(chaindb,tx_tmp,height) < 1:
					#if scan_tx(chaindb,tx_tmp) < 1:
					#print "Error!!!"
					failures += 1
		else:
			print "Error: No data"
		
		scanned += 1

	#log.write("End Height: %d %d %d" % (start_height,height,end_height))
		if (height % 100 == 0):
			sys.stdout.flush()

def main():
		chaindb = chaindb_init()
		scan_block_range(chaindb,int(sys.argv[1]),int(sys.argv[2]))

if __name__ == "__main__":
    main()
