//no// 
//partial// gcc -w -lm -no-pie -fno-stack-protector -Wl,-z,relro -masm=intel -o resolve_partial_relro resolve_me.c
//full// gcc -w -lm -no-pie -fno-stack-protector -Wl,-z,now -masm=intel -o resolve_full_relro resolve_me.c

#include <stdio.h>


int init(){

	setvbuf(stdin,0x0,2,0);
    setvbuf(stdout,0x0,2,0);
    return;
}

int vuln(){

	char vulnbuf[16];

	read(0,&vulnbuf,0x216);

    return;
}

int gift(){

	asm("pop rdx;");
	asm("ret;");

}


int main(){
	init();
    vuln();
    
    return 0;
}
