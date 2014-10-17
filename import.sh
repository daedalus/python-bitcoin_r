#!/bin/bash
while read line;
do
	./import_tx.py $line 
done < $1
