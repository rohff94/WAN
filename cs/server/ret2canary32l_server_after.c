#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

#define SUCCESS 0
#define ERROR   1

#define SERVER_PORT 1500
#define MAX_MSG 1500
#define UNKN_COMM "Unknow command\n"
#define UNKN_USER "Unknow user\n"
#define WELCOME_GHOR "Welcome ghorg0re/3ey\n"


void error(char *msg)
{
	perror(msg);
	exit(-1);
}

int checkUser(char *szBuffer)
{
	char szUser[50];
	int i;

	bzero(szUser, sizeof(szUser));
	strcpy(szUser, &szBuffer[5]);
	for(i=0;i<sizeof(szUser);i++)
	{
		// To Upper
		if((szUser[i] > 'a') && (szUser[i] < 'z'))
			szUser[i] -= 0x20;
	}

	if(!strncmp(szUser, "GHORG0REBEY", strlen("GH0RG0REBEY")))
		return 0;
	return 1;
}

int main (int argc, char *argv[])
{
	int socketfd, newSocketfd, cliLen;
	struct sockaddr_in cliAddr, servAddr;
	char szBuffer[MAX_MSG];
	int n;

	printf("Current stack: 0x%x\n",szBuffer);

	// Create socket
	if((socketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		error("Cannot open socket ");
  
	// Bind to port
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(SERVER_PORT);
  
	if(bind(socketfd, (struct sockaddr *) &servAddr, sizeof(servAddr))<0)
		error("Cannot bind port ");

	listen(socketfd,5);

	printf("%s: waiting for data on port TCP %u\n",argv[0],SERVER_PORT);
	cliLen = sizeof(cliAddr);
	if((newSocketfd = accept(socketfd, (struct sockaddr *) &cliAddr, &cliLen)) < 0)
		error("Cannot accept connection");
	
	snprintf(szBuffer, sizeof(szBuffer), "Welcome to ghorg0re/3ey server\n");
	if((n = write(newSocketfd,szBuffer,strlen(szBuffer))) < 0)
		error("ERROR writing to socket");
  
	bzero(szBuffer, sizeof(szBuffer));
	while((n = read(newSocketfd, szBuffer, MAX_MSG)) > 0)
	{
		if(!strncmp(szBuffer, "USER ", strlen("USER ")))
		{
			if(!checkUser(szBuffer))
			{
				if((n = write(newSocketfd, WELCOME_GHOR, strlen(WELCOME_GHOR))) < 0)
					error("ERROR writing to socket");
			}
			else
			{
				if((n = write(newSocketfd, UNKN_USER, strlen(UNKN_USER))) < 0)
					error("ERROR writing to socket");
			}
		}
		else
		{
			if((n = write(newSocketfd, UNKN_COMM, strlen(UNKN_COMM))) < 0)
				error("ERROR writing to socket");
		}

		bzero(szBuffer, sizeof(szBuffer));
	}
	exit(0);
}

