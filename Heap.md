### in progress

first some pointer overview we need this to understand linked list

```
* pointer 
** double-pointer 
& address of variable

access the value of num
num == *pr2 == **pr1 

value of pr2 == addr of num (&num) 

with *pr2 we access the value of the addr stored in pr2 which is the addr of num (&num).


value of pr1 = addr of pr2 (&pr2)

with **pr1 we access the value of where pr2 points to.
pr2 holds the addr of num (&num) so we will access the value of num 


addr of num
&num == pr2 == *pr1 

addr of pr2
&pr2 == pr1

```
<img src="https://github.com/Bex32/Pwn-Notes/blob/main/src/pointer-to-pointer.png">
