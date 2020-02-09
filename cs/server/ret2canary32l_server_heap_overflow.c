#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>


#define SERVER_PORT 1500
#define MSG_UKN_CMD "Unknow command\n"
#define SZ_USERNAME 200
#define SZ_BUFFER 1500
#define CMD_USER 1

/*************************************
 * Fonction error
 *
 * Affiche le message d'erreur msg
 *
 *************************************/

void error(char *msg)
{
	perror(msg);
	exit(-1);
}

/*************************************
 * Definition des structures
 *
 * CONNEXION: enregistre l'heure de la connexion
 *
 *************************************/

typedef struct
{
	time_t connectTime;
} CONNEXION;


/*************************************
 * Fonction processData
 *
 * Analyse le message szBuffer et renvoie une reponse sur newSocketfd
 *
 *************************************/

void processData(int newSocketfd, char *szBuffer)
{
	char		*p;
	CONNEXION	*c;

	// La commande recu est un login
	if(szBuffer[0] == CMD_USER)
	{
		// Allour un buffer de taille SZ_USERNAME et une structure CONNEXION
		p=(char *) malloc(SZ_USERNAME*sizeof(char));
		c=(CONNEXION *) malloc(sizeof(CONNEXION));

		// Rempli les structures
		c->connectTime=time();
		sprintf(p,"%s login\n", &szBuffer[1]);

		// Renvoie la reponse au client
		if(write(newSocketfd, p, strlen(p)) < 0)
			error("ERROR writing to socket");

		// Libere la memoire
		free(p);
		free(c);

	}
	// La commande recu est inconnue
	else
	{
		if(write(newSocketfd, MSG_UKN_CMD, strlen(MSG_UKN_CMD)) < 0)
			error("ERROR writing to socket");
	}
}

/*************************************
 * Fonction main
 *
 * Cree un serveur en ecoute sur le port SERVER_PORT
 *
 *************************************/

int main (int argc, char *argv[])
{
	int socketfd, newSocketfd, cliLen;
	struct sockaddr_in cliAddr, servAddr;
	char szBuffer[SZ_BUFFER];
	int n;

	// Cree socket
	if((socketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		error("Cannot open socket ");
  
	// Bind sur le port
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(SERVER_PORT);
  
	if(bind(socketfd, (struct sockaddr *) &servAddr, sizeof(servAddr))<0)
		error("Cannot bind port ");

	listen(socketfd,5);

	printf("%s: waiting for data on port TCP %u\n",argv[0],SERVER_PORT);
	cliLen = sizeof(cliAddr);

	// Attente d'un client
	if((newSocketfd = accept(socketfd, (struct sockaddr *) &cliAddr, &cliLen)) < 0)
		error("Cannot accept connection");
	
	// Envoie banner d'accueil
	snprintf(szBuffer, sizeof(szBuffer), "Welcome to ghorg0re/3ey server\n");
	if((n = write(newSocketfd,szBuffer,strlen(szBuffer))) < 0)
		error("ERROR writing to socket");
  
	// Boucle de reception de message
	bzero(szBuffer, sizeof(szBuffer));
	while((n = read(newSocketfd, szBuffer, SZ_BUFFER)) > 0)
	{
		processData(newSocketfd, szBuffer);
		bzero(szBuffer, sizeof(szBuffer));
		
	}
}

