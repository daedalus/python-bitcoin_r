#!/usr/bin/env python
import string
import cStringIO
import leveldb
import ChainDb
import MemPool
import Log
import io
import os
import sys
import time
from decimal import Decimal
from Cache import Cache
from bitcoin.serialize import *
from bitcoin.core import *
from bitcoin.messages import msg_block, message_to_str, message_read
from bitcoin.coredefs import COIN
from bitcoin.scripteval import VerifySignature

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

msg_start = "f9beb4d9".decode('hex')
#msg_start = "mainnet"

SKIP_TX = []

def loadfile(filename):
	fd = os.open(filename, os.O_RDONLY)
	#self.log.write("IMPORTING DATA FROM " + filename)
	buf = ''
	wanted = 4096
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

		#self.putblock(block)
		scan_vtx(block)

def scan_vtx(block):
	scanned_tx = 0
	failures = 0 
        for tx_tmp in block.vtx:
                if tx_tmp.is_coinbase():
                        continue
                scanned_tx += 1
                if not scan_tx(tx_tmp):
                        failures += 1
                        sys.exit(1)

def scan_tx(tx):
        tx.calc_sha256()

        if tx.sha256 in SKIP_TX:
                return True

        for i in xrange(len(tx.vin)):
                txin = tx.vin[i]
                txfrom = chaindb.gettx(txin.prevout.hash)
                if not VerifySignature(txfrom, tx, i, 0):
                        log.write("TX %064x/%d failed" % (tx.sha256, i))
                        log.write("FROMTX %064x" % (txfrom.sha256,))
                        log.write(txfrom.__repr__())
                        log.write("TOTX %064x" % (tx.sha256,))
                        log.write(tx.__repr__())
                        return False
        return True

def chaindb_init():
        chaindb = ChainDb.ChainDb(SETTINGS,SETTINGS['db'], log, mempool,
                          NETWORKS[MY_NETWORK], True)
        chaindb.blk_cache.max = 1000
        return chaindb



#loadfile("/home/dclavijo/dclavijo_remote/.bitcoin/blk0001.dat")

if (len(sys.argv)>0):
	tx = sys.argv[1]
	chaindb = chaindb_init()
	hash = int(tx,16)
	txfrom = chaindb.gettx(hash)
	print scan_tx(txfrom)
	#print txfrom




