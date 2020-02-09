#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/if.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>


int setup_interface(char *device) /*met la carte reseau en mode promiscuous */
{
  int fd;
	struct ifreq ifr;
	int s;

	//open up our magic SOCK_PACKET
	//fd=socket(AF_INET, SOCK_PACKET, htons(ETH_P_IP));
	fd=socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));

	if(fd < 0)
	{
		perror("cant get SOCK_PACKET socket");
		exit(0);
	}

	//set our device into promiscuous mode
	strcpy(ifr.ifr_name, device);
	s=ioctl(fd, SIOCGIFFLAGS, &ifr);
	if(s < 0)
	{
		close(fd);
		perror("cant get flags");
		exit(0);
	}
	// ifconfig eth0 -promisc -> eleve 'UP BROADCAST RUNNING PROMISC MULTICAST' -> 'UP BROADCAST RUNNING MULTICAST'

	//ifr.ifr_flags |= IFF_PROMISC;
	ifr.ifr_flags |= IFF_MULTICAST;
	s=ioctl(fd, SIOCSIFFLAGS, &ifr);
	if(s < 0) perror("cant set promiscuous mode");
	return fd;
}

int main()
{
  int sock, octets_recus, lendata, j, i=0;
  unsigned char *so, *dest;
  struct recvpacquet       /* Les trames seront stockes la avant d'etre traiter */
  {
    struct ethhdr eth;
    struct iphdr  ip;
    struct tcphdr tcp;
    char data[8000];
  } buffer;

  struct iphdr *ip;        /* Utiliser pour le decalage de 2 octets */
  struct tcphdr *tcp;      /*     "       "         "           "   */
  char *data;              /*     "       "          "           "  */

  ip=(struct iphdr *)(((unsigned long)&buffer.ip)-2); /* On pointe 2 octets AVANT */
  tcp=(struct tcphdr *)(((unsigned long)&buffer.tcp)-2); /*   "       "       "   */


  so = (unsigned char *)&(ip->saddr);   /* Utiliser pour affciher les adresses ip */
  dest = (unsigned char *)&(ip->daddr); /*      "         "              "      " */

  sock = setup_interface("eth0");/* mise en mode promiscuous */
  while(1) /*Il aurait fallut gerer les signaux pour fermer la socket en partant :( */
    {
    octets_recus = read(sock, (struct recvpacquet *)&buffer, sizeof(struct recvpacquet));
      i++;
      printf("\n-------Packet \033[37;41;1m%d\033[0m---------\n", i);
	/* On affcihe les adresses ips */
      printf("Adress ::: \t\033[33;1m%u.%u.%u.%u\033[0m:\033[32;1;4m%d\033[0m -----> \033[33;1m%u.%u.%u.%u\033[0m:\033[32;1;4m%d\033[0m\n",
                                   so[0],so[1],so[2],so[3],ntohs(tcp->source),
                           dest[0],dest[1],dest[2],dest[3],ntohs(tcp->dest));
     // printf("Port ::: %d  -------> %d\n",ntohs(tcp->source), ntohs(tcp->dest));
     // printf("TTL ::: %d\n", ip->ttl);
     // printf("Flags ::: SYN=%d | ACK=%d | RST=%d | FIN=%d\n",tcp->syn, tcp->ack, tcp->rst, tcp->fin);

      data=(char *)(((unsigned long)buffer.data)-2); /*La gestion des donnees est foireuse */
      lendata = octets_recus - 2 - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr));
      printf("\033[36;1mDATA: (%u)\033[0m \033[37;1m",lendata);                             /* C juste un exemple */
      for (j=0 ; j <= lendata ; j++)
 	printf("%c", data[j]);
      printf("\033[0m\n");
    }
 }
