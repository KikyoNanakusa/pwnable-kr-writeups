from pwn import *
import os

binary_path = './input'

# Stage1
arguments = ['a'] * 100
arguments[65] = '\x00'
arguments[66] = '\x20\x0a\x0d'
arguments[67] = '8888'

#Stage2
r1, w1 = os.pipe()
r2, w2 = os.pipe()
os.write(w1, b'\x00\x0a\x00\xff')
os.write(w2, b'\x00\x0a\x02\xff')

# Stage4
with open('\x0a', 'w') as f:
    f.write('\x00\x00\x00\x00')

io = process(executable=binary_path, argv=arguments, 
             stdin=r1, stderr=r2,
             env={'\xde\xad\xbe\xef' :'\xca\xfe\xba\xbe'}) # Stage3

# Stage5
process_host = remote("localhost", 8888)
process_host.sendline("\xde\xad\xbe\xef")

io.interactive()