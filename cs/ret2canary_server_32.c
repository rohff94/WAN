#include <stdio.h>
#include <sys/socket.h>       /*  socket definitions        */
#include <sys/types.h>        /*  socket types              */
#include <arpa/inet.h>        /*  inet (3) funtions         */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>


#define SERVER_PORT 9999
#define LISTENQ (1024+512)
#define MAX_CHILDREN 1
#define BUFFER_SIZE 512

typedef unsigned long can_t;
#define can_fmt "%0lx"
#define get_canary(can) \
asm volatile("mov %%gs:(0x14), %0" : "=r" (can));

#define __stringify_1(x...) #x 
#define __stringify(x...)   __stringify_1(x)

#define PANIC(fmt, ...) \
    do { \
        printf("System Panic !!! \n\n"); \
        printf("["__FILE__":"__stringify(__LINE__)"] %s " fmt, __FUNCTION__, ## __VA_ARGS__); \
        exit(-1); \
    }while(0);

struct sockaddr_in servaddr;
int sock_fd;

void create_tcp_socket(void) {
  if((sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    PANIC("Can't create TCP socket");
}

void wait_a_child(void){
   int status;
   if( waitpid(-1, &status, 0) == -1)
      PANIC("wait_a_child returned -1 \n");
}


 

/* 
 * This is a dummy function which contain a simple buffer overflow
 */
void vulnerable_function(int *srcbuff){
   int i;
   	char buff[256];
    
    memset(buff, '\0', 256);

   read(*srcbuff, buff, 512);
 //memcpy(buff,srcbuff, strlen(srcbuff));
 //strncpy(buff,srcbuff, 512);

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




void startServer(void){

   create_tcp_socket();

   /*  Populate socket address structure  */
   memset(&servaddr, 0, sizeof(servaddr));
   servaddr.sin_family      = AF_INET;
   servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
   servaddr.sin_port        = htons(SERVER_PORT);

   /*  Assign socket address to socket  */
   if ( bind(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 )
       PANIC("Couldn't bind listening socket.");

   /*  Make socket a listening socket  */
   if ( listen(sock_fd, LISTENQ) < 0 )
       PANIC("Call to listen failed.");

}

void attend_non_return(void){

   int sock_c;
   int res;
   char buf[BUFFER_SIZE];
   char msg1[]="Welcome to a simple webserver\n";
   char msg2[]="All done, bye!\n";
   struct timeval tv;
   int i;
   can_t can;



   write(1,".", 1);
   if ( (sock_c = accept(sock_fd, NULL, NULL)) < 0 )
      PANIC("Error calling accept()");
  
   close(sock_fd);

   // You can optimize waiting via timeout
   tv.tv_sec=0,tv.tv_usec=400000; //400ms timeout
   if ( (setsockopt(sock_c,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv))) != 0)
      PANIC("setsockopt() error!\n");

   // Read from client (not be used for anything)
   res = read(sock_c, buf, BUFFER_SIZE);
   if(res <= 0)
      PANIC("Error reading from request client\n");
  
   // Send banner to client
   write(sock_c, msg1, strlen(msg1));
   if( res <= 0)
      PANIC("Error sending banner to client\n");

   // Read payload from client
  res = read(sock_c, buf, BUFFER_SIZE);

   get_canary(can);
   printf("\n\nBefore GS at offset 0x14 : " can_fmt "\n", can);
   
   // Functions which contain a buffer overflow
   vulnerable_function(&sock_c);

   get_canary(can);
   printf("After GS at offset 0x14 : " can_fmt "\n", can);
    // If all was right print bye msg
   write(sock_c, msg2, strlen(msg2));


   close(sock_c);
   printf("Exit child\n");
   exit(0);
}


int main(void){

   pid_t pid;
   int children = 0;

   printf("Starting server on port [%d]\n", SERVER_PORT);
   startServer();

   while(1){
      if(MAX_CHILDREN <= children){
         //printf("[Server Log] %d children created\n", children);
         wait_a_child();
         children--;
      }
      pid = fork();

      if(pid<0)
         PANIC("fork() failed!!!\n");

      if (pid == 0)
         attend_non_return();

      children++;
   }

   return 0;
} 
