# input
以下のコードが渡される
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}
```

条件に合致するように入力を調整すればよい

## Stage1
```c
	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	
```

- 引数の数を100にする
- 引数の65番目( = A)が`\x00`
- 引数の66番目( = B)が`\x20\x0a\x0d`
以上の条件を満たせばよい

## Stage2
```c
// stdio
char buf[4];
read(0, buf, 4);
if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
read(2, buf, 4);
	if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
printf("Stage 2 clear!\n");
```

- 標準入力に`\x00\x0a\x00\xff`が書き込まれている
- 標準エラーに`\x00\x0a\x02\xff`が書き込まれている
以上を満たせばよい

## Stage3
```c
// env
if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
printf("Stage 3 clear!\n");
```

- 環境変数`\xde\xad\xbe\xef`に`\xca\xfe\xba\xbe`が設定してあればよい

## Stage4
```c
// file
FILE* fp = fopen("\x0a", "r");
if(!fp) return 0;
if( fread(buf, 4, 1, fp)!=1 ) return 0;
if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
fclose(fp);
printf("Stage 4 clear!\n");	
```

- ファイル名`\x0a`に対して`\x00\x00\x00\x00`が書き込んであればよい

## Stage5
```c
// network
int sd, cd;
struct sockaddr_in saddr, caddr;
sd = socket(AF_INET, SOCK_STREAM, 0);
if(sd == -1){
	printf("socket error, tell admin\n");
	return 0;
}
saddr.sin_family = AF_INET;
saddr.sin_addr.s_addr = INADDR_ANY;
saddr.sin_port = htons( atoi(argv['C']) );
if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
	printf("bind error, use another port\n");
		return 1;
}
listen(sd, 1);
int c = sizeof(struct sockaddr_in);
cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
if(cd < 0){
	printf("accept error, tell admin\n");
	return 0;
}
if( recv(cd, buf, 4, 0) != 4 ) return 0;
if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
printf("Stage 5 clear!\n");
```

- 67番目(= C)の引数のポートでリッスン
- `\xde\xad\xbe\xef`が送られてくればよい

## Solver
以上をすべて満たすソルバーが以下である
```python
from pwn import *
import os

# binary_path = './input'
binary_path = '/home/input2/input'

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
```

flag: Mommy! I learned how to pass various input in Linux :)