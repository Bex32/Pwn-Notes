//gcc easy_one.c -o opt -w -Wfloat-equal -m32 -fno-stack-protector -g
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(){
  char overflow[16];

  puts("a");
  gets(overflow);
  return 0;
}
