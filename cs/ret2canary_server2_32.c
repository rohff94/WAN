#include <stdio.h>
#include <sys/socket.h>       /*  socket definitions        */
#include <sys/types.h>        /*  socket types              */
#include <arpa/inet.h>        /*  inet (3) funtions         */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

typedef unsigned long can_t;
#define can_fmt "%0lx"
#define get_canary(can) \
asm volatile("mov %%gs:(0x14), %0" : "=r" (can));


int ssock;
long find_esp() {
asm("movl %esp, %eax");
}


void bar(int *sock)
{
    
	int i;
	char buff[256];
    
    memset(buff, '\0', 256);

    read(*sock, buff, 512);
printf("receive %d data : %s \n",strlen(buff),buff);
printf("&buff = 0x%02x : %02x : %c \n",buff,buff[0],buff[0]);
printf("Canary = 0x");
for(i=259;i>255;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");

printf("PAD1 = 0x");
for(i=263;i>259;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");


printf("PAD2 = 0x");
for(i=267;i>263;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");


printf("PAD3 = 0x");
for(i=271;i>267;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");


printf("PAD4 = 0x");
for(i=275;i>271;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");
printf("PAD5 = 0x");
for(i=279;i>275;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");
printf("PAD6 = 0x");
for(i=283;i>279;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");
printf("PAD7 = 0x");
for(i=287;i>283;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");
printf("PAD8 = 0x");
for(i=291;i>287;i--)
printf("%02x",(unsigned char)*(buff+i));
printf("\n");
}

int foo(void)
{
    int csock;
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    char buffer[512];
    can_t can;

    if( (csock = accept(ssock, (struct sockaddr *) &caddr, &clen)) < 0)
    {
        exit(1);
    }

  
   get_canary(can);
   printf("\n\nBefore GS at offset 0x14 : " can_fmt "\n", can);
    memset(buffer, '\0', 512);

    bar(&csock);
    send(csock, "Recu", 5, 0);
   get_canary(can);
   printf("After GS at offset 0x14 : " can_fmt "\n", can);
    close(csock);


    return 0;
}

int main(void)
{
    int pid, flag = 1;
    struct sockaddr_in saddr;

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(9999);

    while(1)
    {
        pid = fork();

        if( pid == 0 )
        {
            if( (ssock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
            {
                exit(1);
            }

            if(setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int)) <0)
            {
                exit(1);
            }

            if( bind(ssock, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
                exit(1);
            }

            if( listen(ssock, 5) < 0)
            {
                exit(1);
            }

            foo();
        }
        else
        {
            wait(NULL);
            close(ssock);
        }
    }

    return 0;
}

