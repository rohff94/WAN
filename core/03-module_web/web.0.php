<?php


class WEB extends SERVICE4COM{

    var $web ;
    var $vhost ;
	var $http_type ;
	var $web2where ;
	var $cookies ;

	
	/*
	https://www.exploit-db.com/exploits/33023      Apache Tomcat < 6.0.18 - Form Authentication Existing/Non-Existing 'Username' Enumeration   
	https://hackingresources.com/web-application-penetration-testing-course/
	 */
	
	public function __construct($eth,$domain,$web) {		
	    if (empty($web)) return $this->rouge("EMPTY WEB");
	    $this->web = trim($web);
	    $this->vhost = parse_url( $this->web, PHP_URL_HOST);
	    $this->http_type = parse_url( $this->web, PHP_URL_SCHEME);

	    
	    if (parse_url( $this->web, PHP_URL_PORT)!==FALSE) $port = parse_url( $this->web, PHP_URL_PORT);
	    else {
	        if($this->http_type=="https") $port = 443 ;
	        if($this->http_type=="http") $port = 80;
	    }
	    
	    
	    parent::__construct($eth,$domain,$this->vhost,$port,'T');	
	    $this->web2where = "id8port = '$this->port2id' AND vhost = '$this->vhost' ";
	    
		$sql_r = "SELECT vhost FROM ".__CLASS__." WHERE $this->web2where";
		if (!$this->checkBD($sql_r)) {
			$sql_w = "INSERT  INTO ".__CLASS__." (id8port,vhost) VALUES ('$this->port2id','$this->vhost'); ";
			$this->mysql_ressource->query($sql_w);
			//echo "$sql_w\n";
			echo $this->note("Working on WEB :$this->web for the first time");
		}
	}
	
	/*
	 /opt/metasploit/apps/pro/msf3/data/wordlists/sensitive_files.txt
	 /opt/metasploit/apps/pro/msf3/data/wordlists/sensitive_files_win.txt
	 *
	 *
	 * Long URL formatting just changes into a non-existent directory, and then to its parent. The idea is that the web Server itself will parse out this
	 nonsense, but the IDS is likely just looking in the first 30 or so characters for signature matching.
	 GET /bunchofjunkbunchofjunkbunchofjunkbunchofjunk/ ../cgi-bin/mycgi.cgi HTTP/1.0
	
	
	 *
	 *Cookie poisoning :
	
	 https://www.trustworthyinternet.org/ssl-pulse/
	
	
	 --retry 10 -w 200
	 curl --connect-timeout 5 \
	 --max-time 10 \
	 --retry 5 \
	 --retry-delay 0 \
	 --retry-max-time 60 \
	 'http://www.site.com/download/file.txt'
	
	
	 <?php
	 $fp = stream_socket_client("tcp://www.example.com:80", $errno, $errstr, 30);
	 if (!$fp) {
	 echo "$errstr ($errno)<br />\n";
	 } else {
	 fwrite($fp, "GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: *\r\n\r\n");
	 while (!feof($fp)) {
	 echo fgets($fp, 1024);
	 }
	 fclose($fp);
	 }
	 ?>
	
	
	 <?php
	 $fp = fsockopen("www.example.com", 80, $errno, $errstr, 30);
	 if (!$fp) {
	 echo "$errstr ($errno)<br />\n";
	 } else {
	 $out = "GET / HTTP/1.1\r\n";
	 $out .= "Host: www.example.com\r\n";
	 $out .= "Connection: Close\r\n\r\n";
	 fwrite($fp, $out);
	 while (!feof($fp)) {
	 echo fgets($fp, 128);
	 }
	 fclose($fp);
	 }
	 
	 $socket = stream_socket_client("ssl://192.168.1.5:8000", $errno, $errstr);
	 if ($socket) {
	 echo fread($socket, 2000);
	 }
	
	 ?>
	 */
	
	
	
	public function cms2file($rep,$target){
	    $this->ssTitre(__FUNCTION__);
	    $tab_file = $this->req_ret_tab("cd $rep; find . -type f  ");
	    if (!empty($tab_file))
	        foreach ($tab_file as $file_php ){
	            $file_php = trim($file_php);
	            $query_burp = "wget --server-response -qO- --no-check-certificate --timeout=2 --tries=1 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port -e https_proxy=$this->proxy_addr:$this->proxy_port \"$target/$file_php\" --user-agent='$this->user2agent' 2>&1 ";
	            $this->requette("echo '$query_burp' >> cmd.sh ");
	            $this->requette($query_burp);
	            $this->requette("wget --server-response -qO- --no-check-certificate --timeout=2 --tries=1 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port_zap -e https_proxy=$this->proxy_addr:$this->proxy_port_zap \"$target/$file_php\" --user-agent='$this->user2agent' 2>&1");
	            //  $this->pause();
	    }
	}
	
	public function cms2get($rep){
	    $this->ssTitre(__FUNCTION__);
	    //for i in `find . -type f -iname "*.php" `;do echo "Traitement sur $i"; grep "\$_GET\[" $i | sed "s/'//g" | sed "s/\"//g" | grep -Po "\$_GET\[[a-zA-Z0-9_\-]{1,}\]"; done
	    //for i in `find . -type f -iname "*.php" `;do echo "Traitement sur $i"; grep "\$_POST\[" $i ; done
	    // for i in `find . -type f -iname "*.php" `;do grep "\$_GET\[" $i | sed "s/'//g" | sed "s/\"//g" | grep -Po "\$_GET\[[a-zA-Z0-9_\-]{1,}\]"; done
	    $tab_file = $this->req_ret_tab("cd $rep; find . -type f -iname \"*.php\" ");
	    foreach ($tab_file as $file_php ){
	        $file_php = trim($file_php);
	        $check = $this->req_ret_tab("cd $rep; cat $file_php | sed \"s/'//g\" | sed \"s/\\\"//g\"  | grep -Po \"_GET\[[a-zA-Z0-9_\-$]{1,}\]\" | sed \"s/_GET\[//g\" | sed \"s/]//g\"  | sort -u ");
	        if (!empty($check)){
	            foreach ($check as $var_get){
	                echo "Variable : $var_get dans le fichier $file_php \n";
	                $query_burp = "wget --server-response -qO- --no-check-certificate --timeout=2 --tries=1 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port -e https_proxy=$this->proxy_addr:$this->proxy_port \"http://kpiw.ooredoo.dz/$file_php?$var_get=Ooredoo\" --user-agent='$this->user2agent' 2>&1";
	                $this->requette("echo '$query_burp' >> cmd.sh ");
	                $this->requette($query_burp);
	                $this->requette("wget --server-response -qO- --no-check-certificate --timeout=2 --tries=1 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port_zap -e https_proxy=$this->proxy_addr:$this->proxy_port_zap \"http://kpiw.ooredoo.dz/$file_php?$var_get=Ooredoo\" --user-agent='$this->user2agent' 2>&1");
	                $this->pause();
	            }
	        }
	    }
	}
	
	
	public function cms2post($rep){
	    $this->ssTitre(__FUNCTION__);
	    $tab_file = $this->req_ret_tab("cd $rep; find . -type f -iname \"*.php\" ");
	    foreach ($tab_file as $file_php ){
	        $file_php = trim($file_php);
	        $check = $this->req_ret_tab("cd $rep; cat $file_php | sed \"s/'//g\" | sed \"s/\\\"//g\"  | grep -Po \"_POST\[[a-zA-Z0-9_\-$]{1,}\]\" | sed \"s/_POST\[//g\" | sed \"s/]//g\"  | sort -u ");
	        if (!empty($check)){
	            foreach ($check as $var_get){
	                echo "Variable : $var_get dans le fichier $file_php \n";
	                $query_burp = "wget --server-response -qO- --no-check-certificate --timeout=2 --tries=1 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port -e https_proxy=$this->proxy_addr:$this->proxy_port  \"http://kpiw.ooredoo.dz/$file_php\" --post-data \"$var_get=Ooredoo\" --user-agent='$this->user2agent' 2>&1";
	                $this->requette("echo '$query_burp' >> cmd.sh ");
	                $this->requette($query_burp);
	                $this->requette("wget --server-response -qO- --no-check-certificate --timeout=2 --tries=1 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port_zap -e https_proxy=$this->proxy_addr:$this->proxy_port_zap \"http://kpiw.ooredoo.dz/$file_php\" --post-data \"$var_get=Ooredoo\" --user-agent='$this->user2agent' 2>&1");
	                //  $this->pause();
	            }
	        }
	    }
	}
	
	
	public function cms2web($rep){
	    $this->ssTitre(__FUNCTION__);
	    //for i in `find . -type f -iname "*.php" `;do echo "Traitement sur $i"; grep "\$_GET\[" $i | sed "s/'//g" | sed "s/\"//g" | grep -Po "\$_GET\[[a-zA-Z0-9_\-]{1,}\]"; done
	    //for i in `find . -type f -iname "*.php" `;do echo "Traitement sur $i"; grep "\$_POST\[" $i ; done
	    // for i in `find . -type f -iname "*.php" `;do grep "\$_GET\[" $i | sed "s/'//g" | sed "s/\"//g" | grep -Po "\$_GET\[[a-zA-Z0-9_\-]{1,}\]"; done
	    $this->cms2file($rep);
	    $this->cms2get($rep);
	    $this->cms2post($rep);
	}
	

	
	
	public function web2dot(){	
		$file_output = "$this->vhost.$this->ip.$this->port.".__FUNCTION__.".dot";
		$color_dns = "steelblue";$color_host = "steelblue";$color_web = "steelblue";$color_arrow = "greens4";
		$web2dot_header = "digraph structs {
	label = \"".__FUNCTION__.":$this->vhost\";
			graph [rankdir = \"LR\" layout = dot];
			node [fontsize = \"16\" shape = \"plaintext\"];
			edge [penwidth=2.0 ];";
		
			$web2dot_vhost = "
			\"$this->ip.$this->vhost.$this->port\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">
		<TR><TD>VHOST</TD><TD PORT=\"vhost\" bgcolor=\"$color_web\">$this->vhost</TD></TR>
		<TR><TD>IP:PORT</TD><TD PORT=\"ip\" >".$this->dot2diagram(str_replace("\n","<BR/>\n","$this->ip:$this->port"))."</TD></TR>	
		<TR><TD>WEB2ENUM</TD><TD PORT=\"web2enum\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->web2enum()))."</TD></TR>
		</TABLE>>];
				";
			// 	<TR><TD>FUZZ</TD><TD PORT=\"web2fuzz\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->web2fuzz()))."</TD></TR>
			// 	<TR><TD>SCAN4CLI</TD><TD PORT=\"web2scan4cli\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->web2scan4cli()))."</TD></TR>
			// 	<TR><TD>MIRRORING</TD><TD PORT=\"web2mirror\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->web2mirror()))."</TD></TR>
			// 	<TR><TD>PHP VERSION</TD><TD PORT=\"web2php\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->web2php()))."</TD></TR>
			// <TR><TD>WAF</TD><TD PORT=\"web2waf\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->web2waf()))."</TD></TR>
			// <TR><TD>WEB2DICO</TD><TD PORT=\"web2dico\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->web2dico4file()))."</TD></TR>
			// <TR><TD>WEB2SPIDER</TD><TD PORT=\"web2spider\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->web2spider()))."</TD></TR>
			// <TR><TD>WEB SCREENSHOT</TD><TD PORT=\"web2screenshot\" ><IMG SRC=\"".$this->web2screenshot()."\" /></TD></TR>	
		
		$web2dot_footer = "
		}";
		
		$web2dot = $web2dot_header.$web2dot_vhost.$web2dot_footer;
		$web2dot4body = $web2dot_vhost;
		//system("echo '$web2dot' > $file_output ");
		//$this->requette("gedit $file_output");
		
		//$this->dot4make($file_output,$web2dot);
		//$this->dot2xdot($file_output);
		return $web2dot4body;
		}
		
		public function web2enum4dav(){
		    $result = "";
		    $result .= $this->ssTitre(__FUNCTION__);
		    $query = "davtest -url \"$this->http_type://$this->vhost:$this->port/\" 2>&1 ";
		    $result .= $this->cmd("localhost",$query);
		    $result .= $this->req_ret_str($query);
		    return $result;
		}

		public function web2enum4bing(){
		    $result = "";
		    $result .= $this->ssTitre(__FUNCTION__);
		    $query = "parsero -u \"$this->http_type://$this->vhost:$this->port/\" 2>&1 ";
		    $result .= $this->cmd("localhost",$query);
		    $result .= $this->req_ret_str($query);
		    return $result;
		}
		public function web2scan4cli4commix(){
		    $result = "";
		    $result .= $this->ssTitre(__FUNCTION__);
		    $query = "commix --batch -u \"$this->http_type://$this->vhost:$this->port/\" --all --level 3 2>&1 ";
		    $result .= $this->cmd("localhost",$query);
		    $result .= $this->req_ret_str($query);
		    return $result;
		}

		
		public function web4pentest(){
		    $result = "";
		    $tab_urls = array();
		    $this->gtitre(__FUNCTION__);
		    
		    
		    $cms = $this->web2cms();
		    if (!empty($cms)){
		        $this->ssTitre("Searching exploit associate to CMS");
		        $exploits_db = $this->tab($this->exploitdb($cms));
		        $this->article("Exploits 8 DB", $exploits_db);
		        $result .= $exploits_db;
		    
		    $exploits_msf = $this->msf2search2info($cms);
		    $this->article("Exploits 8 MSF", $exploits_msf);
		    $result .= $exploits_msf;
		    //echo $exploits;
		    
		    $this->msf2search2exec($cms);
		    }
		    
		    
		    
			$tab_urls = $this->web2urls();
			$this->article("ALL URLs For Testing", $this->tab($tab_urls));
			$this->pause();
			
            if ( !empty($tab_urls)  ) {			
				//$result .= $this->web2waf();
				//$this->web2scan4gui4zap();$this->pause();
				
                $file_path = "/tmp/$this->eth.$this->domain.$this->ip.$this->port.urls";
                $fp = fopen($file_path, 'w+');
                foreach ($tab_urls as $url){
                    $url = trim($url);
                    if(!empty($url)){
                        $data = "$this->eth $this->domain $url url4pentest FALSE";
                        $data = $data."\n";
                        fputs($fp,$data);
                    }
                }
                fclose($fp);
                
                $query = "gedit $file_path";
                $this->requette($query);
                
                //$this->requette("cat $file_path | parallel --progress --no-notice -k -j24 php pentest.php URL {} ");

                
                $tab_urls = $this->req_ret_tab("awk '{print $3}' $file_path ");
			foreach ($tab_urls as $url){
			    $url = trim($url);			    
			    if(!empty($url)){
			$obj_url = new URL($this->eth,$this->domain,$url);	
			$obj_url->poc($this->flag_poc);
			$result .= $obj_url->url4pentest();
			$this->pause();
			    }
			                             }
			                                     }					
			return $result;
		}
		
		
		
		
		public function web2check_200(){
		    $this->ssTitre(__FUNCTION__);
		    if ($this->url2code($this->web)==="200") return TRUE ; else return FALSE ;
		}
		
		public function web2robots(){
		    $query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn --script=\"http-robots.txt\" $this->vhost -p $this->port -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/ports/port/script/@output | strings "; // --script \"http-enum,http-title,http-traceroute,http-methods,http-headers,http-method-tamper\"
		    return $this->req_ret_str($query);
		}
		
		public function web2cms(){
		    $this->ssTitre(__FUNCTION__);
		    $query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn --script=\"http-generator\" $this->vhost -p $this->port -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/ports/port/script/@output | strings "; // 
		    return $this->req_ret_str($query);	
		}
		
		public function web2urls(){
		    $this->titre(__FUNCTION__);
		    $tab_result = array();
		    $tab_tmp = array();
		    $tab_tmp2 = array();
		    $tab_enum1 = array();
		    $tab_enum2 = array();
		    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->web2where AND ".__FUNCTION__." IS NOT NULL";
		    if ($this->checkBD($sql_r_1) ) return  explode("\n", base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,$this->web2where)));
		    else {
		        
		        $robots = $this->web2robots();
		        echo $robots;
		        exec("echo '$robots' $this->filter_file_path ",$tmp_robots);
		        
		        
		        
		    
		        $nmap = $this->web2enum();
		        echo $nmap;
		        exec("echo '$nmap' $this->filter_file_path ",$tab_enum1);
		        
		        $this->pause();
		        $scancli = $this->web2scan4cli();
		        exec("echo '$scancli' $this->filter_file_path ",$tab_enum2);
		        var_dump($tab_enum2);
		        $this->pause();
		        $tab_tmp = array_merge($tab_enum1,$tab_enum2,$tmp_robots);
		        $tab_tmp = array_filter(array_unique($tab_tmp));
		        $this->pause();
		        foreach ($tab_tmp as $uri ){
		            $tab_tmp2[] = "$this->http_type://$this->ip:$this->port".trim($uri);
		        }
		        $tab_tmp = array_filter(array_unique($tab_tmp2));
		        $tab_result = array_merge($tab_tmp,$this->web2urls4spider()); // 
		     
		        if (count($tab_result)<50) $tab_result = array_merge($this->web2urls4dico());
				
			
			$tab_result = array_unique($tab_result);
			$result = $this->tab($tab_result);			
			
			//return $tab_result;
			
			$this->pause();
			$result = base64_encode($result);
			return explode("\n", base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,$this->web2where,$result)));
		    }
		}
		
		public function web2enum4user2agent(){
		   $result = "";
		   $result .= $this->ssTitre(__FUNCTION__);
		   $query = "ua-tester -u \"$this->http_type://$this->vhost:$this->port/\" -f $this->dir_tools/dico/user-agent-list.dico -v 2>&1 ";
		   $result .= $this->cmd("localhost",$query);
		   $result .= $this->req_ret_str($query);
		   return $result;;
		}
		
		public function web2screenshot(){
			$this->ssTitre(__FUNCTION__);
			$file_output = "$this->dir_tmp/$this->ip.$this->port.$this->vhost.".__FUNCTION__.".png";		
			$query = "cutycapt --url=$this->vhost --out=$file_output ";
			if (file_exists($file_output)) $this->cmd("localhost", $query);
			else $this->requette($query);		
			$query = "$file_output";
			return $file_output;
		}
	

	
		public function web2path($url,$dico){
		    $this->ssTitre(__FUNCTION__); 
		    $url = trim($url);
		    $dico = trim($dico);
		    $result = array();
		    $req_result_tab = array();
		    $req_result = "";
		    $url_test = "";
		    /*
		    $query = "dirb '$url' '$dico' -a '$this->user2agent' -S -w | grep 'CODE:200' | cut -d'+' -f2 | cut -d'(' -f1 | sort -u  ";
		    
		    $query = "wfuzz -u $this->http_type://$this->vhost:$this->port/FUZZ -w $this->dico_web -H 'user2agent: $this->user2agent' --sc 200  | grep 'C=200' | cut -d'\"' -f2  | cut -d'\"' -f1 | sort -u ";
		    $query = "python $this->dir_tools/enum/Dir-Xcan6.py -s $this->http_type://$this->vhost -d $this->dico_web -u '$this->user2agent' -V -n 8 | grep -Po \"$this->http_type://[[:print:]]*\" | sed \"s#$this->http_type://$this->vhost##g\"  | grep -v ';' | sort -u ";
		    
		    $query = "cd /opt/crawlbox/;python2 crawlbox.py -u '$url' -w '$dico'  | grep '200' ";
		    */
		    $req_dico = file($dico);
		    $size = count($req_dico);
		    for ($i=0;$i<$size;$i++){
		        $url_test = trim($req_dico[$i]);
		        $url_test = "$this->web$url_test";
		        $code = $this->url2code($url_test);
		        $code = trim($code);
		        echo "$i/$size: ".$this->web2response($code);
		        switch ($code) {
		            case "000" :
		            case "301" :
		            case "404" :
		                break;
		            default: 
		                $req_result .= $url_test."\n";
		                break;
		        }
		    }

		    $req_result_tab = explode("\n", $req_result);
		    
		    if (count($req_dico)<=count($req_result_tab)) $result = array("");
		    else $result = $req_result_tab;
		    
		    $this->article("URLs FROM DICO", $this->tab($result)) ;
		    $this->pause();
		    return $result;
		}
	
		public function web2urls4dico(){
           $this->ssTitre(__FUNCTION__);//  -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port --spider 
		
		$dico = $this->dico_web ;
		$tmp1 = $this->web2path($this->web, $dico);		

		$dico = $this->dico_web_file ;
		$tmp2 = $this->web2path($this->web, $dico);
		$this->pause();
		return array_filter(array_unique(array_merge($tmp1,$tmp2)));
	}
	

	
	public function web2enum4google(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);

		$this->requette("firefox -search site:\"$this->vhost\" ");
		$this->requette("firefox -search 'intext:\"error\" site:\"$this->vhost\" '");
		$this->remarque("Add rep list from google");
		//net("https://www.google.fr/search?hl=fr&q=site:$this->vhost");pause();
		//net("https://www.google.fr/search?hl=fr&q=intitle:\"error\"%20site:$this->vhost");pause();
	
		$result .= $this->cmd("localhost",$query);
		//$result .= $this->req_ret_str($query);
		return $result;
	}
	
		
	public function web2scan4gui4vega(){
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost","$this->dir_tools/web/vega/Vega");$this->pause();
	}

	
	public function web2scan4gui4zap(){
		$this->ssTitre(__FUNCTION__);
		// /ZAP_2.4.0/zap.sh -port 8090 -host 0.0.0.0 -newsession /ZAP_2.4.0/session/test8 -daemon &
		// -config scanner.attackOnStart=true -config view.mode=attack
		// -config scanner.attackPolicy=MyAttackPolicy
		
		while (!$this->tcp2open("127.0.0.1", $this->proxy_port_zap)) {
        $filename = "/opt/zaproxy/zap.sh";
        $this->article("ZAP","localproxy $this->proxy_port_burp without connection outgoing  ");        
		$this->cmd("Using TOR","echo '$this->root_passwd' | sudo -S bash $filename -DsocksProxyHost=127.0.0.1-DsocksProxyPort=9050");
		//if(!file_exists($filename)) $this->install_web2scan4gui4zap();
		$this->cmd("localhost","bash $filename");
		sleep(30);
	}
	$this->requette("wget -qO- --no-check-certificate --timeout=2 --tries=1 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port_zap  -e https_proxy=$this->proxy_addr:$this->proxy_port_zap \"$this->web\" --user-agent='$this->user2agent' > /dev/null ");
	
	}
	

	public function web2scan4gui4owtf(){
		$this->ssTitre(__FUNCTION__);
		$filename = "/opt/owtf/owtf.py";
		if(!file_exists($filename)) $this->install_web2scan4gui4owtf();
		
		$this->cmd("localhost","source ~/.bashrc; workon owtf");
		$this->cmd("localhost","python $filename");
		$this->net("http://localhost:8009/ui/");
		$this->pause();
	}
	
	public function web2scan4gui(){
		$this->titre(__FUNCTION__);
		// https://kalilinuxtutorials.com/archery-scan-vulnerabilities/
		// https://kalilinuxtutorials.com/owtf-offensive-web-testing-framework/
	
		$this->article("ZAP","localproxy $this->proxy_port_burp without connection outgoing  ");
		//$this->article("OWTF","Setting/INBOUND PROXY $this->proxy_port_burp  ");
		//$this->article("ZAP","localproxy 8008 - connexion 127.0.0.1:$this->proxy_port_burp - Proxy_1_out ");
		//$this->article("TODO-Maltego","127.0.0.1:$this->proxy_port_zap redirect 127.0.0.1:8083 - Proxy_3 ");
		$this->pause();
		//$this->web2scan4gui4owtf(); // consomme trop de ressources $ echo '$this->root_passwd' | sudo -S ps -aux | grep owtf ; echo '$this->root_passwd' | sudo -S netstat -tupan | grep 8009
		
		//$this->web2scan4gui4burp();
		$this->web2scan4gui4zap();
		$this->pause();
		//$this->web2spider();$this->pause();
		//$this->web2dico4rep();$this->web2dico4file();$this->web2cms();$this->pause();
		$this->web2sqli();$this->pause();
		$this->web2scan4cli();$this->pause();
		
		$this->article("READ REPORT","FROM ARACHNI");
		$this->web2scan4gui4arachni();
		
		$this->web2scan4gui4vega();
		$this->net("http://localhost:9292/scans");
		$this->pause();
		$this->article ( "Pass Nessus To Proxy ZAP", "on $this->proxy_addr:$this->proxy_port" );
		$this->net("https://localhost:8834/nessus6.html#/settings/communication" );
		$this->web2scan4gui4nessus();
		$this->web2scan4gui4msf();
		$this->web2scan4gui4w3af();
		$this->web2scan4gui4nexpose();
		$this->web2scan4gui4armitage();
		$this->web2scan4gui4maltego();
		$this->pause();
		}

	public function web2scan4cli(){
	    $result = "";
	    $this->titre(__FUNCTION__);
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->web2where AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->web2where"));
	    else {
	        	        
		if ($this->web2check_200())
		{
		    // https://kalilinuxtutorials.com/curate-tool-archived-urls/
		$result .= $this->web2scan4cli4nikto(); // OK 		
		//$result .= $this->web2scan4cli4spaghetti(); // OK mais ne sert a rien 
		//$result .= $this->web2scan4cli4arachni(); // ne sert a rien 
		//$result .= $this->web2scan4cli4grabber(); // BUG 
		//$result .= $this->web2scan4cli4uniscan(); // BUG
		// $result .= $this->web2scan4cli4commix();  // OK TROP LONG COMME SQLMAP 
		//$result .= $this->web2scan4cli4golismero();   // NOT YET 
		// $result .= $this->web2scan4cli4sitadel();$this->pause();   // DO NOT USEFULL 
		//if (!$this->ip4priv($this->ip)) $result .= $this->web2scan4cli4vbscan();// OK
		//$result .= $this->web2scan4cli4cmseek();   // OK
		//$result .= $this->web2scan4cli4XAttacker();$this->pause();   // NOT YET 
		}
		

		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->web2where",$result));
	    }
	}
	
	public function web2scan4cli4XAttacker(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/XAttacker")) $this->install_web2scan4cli4XAttacker();
	    $query = "cd /opt/XAttacker; perl XAttacker.pl '$this->http_type://$this->vhost:$this->port'   ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	
	public function web2scan4cli4cmseek(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/CMSeek")) $this->install_web2scan4cli4cmseek();
	    $query = "cd /opt/CMSeeK; python3 cmseek.py -u '$this->http_type://$this->vhost:$this->port'  --user-agent '$this->user2agent'  ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	public function web2scan4cli4vbscan(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/vbscan")) $this->install_web2scan4cli4vbscan();
	    $query = "cd /opt/vbscan; perl vbscan.pl '$this->http_type://$this->vhost:$this->port'  --user-agent '$this->user2agent' ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	public function web2scan4cli4sitadel(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/Sitadel")) $this->install_web2scan4cli4sitadel();
	    $query = "cd /opt/Sitadel; python3 sitadel.py '$this->http_type://$this->vhost:$this->port'  --user-agent '$this->user2agent' -t 2400 ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	public function web2scan4cli4golismero(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "golismero scan '$this->http_type://$this->vhost:$this->port'  --user-agent '$this->user2agent' -q ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	public function web2scan4cli4spaghetti(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "cd /opt/Spaghetti/; python wascan.py --url '$this->http_type://$this->vhost:$this->port' --scan 0,1,2 --agent '$this->user2agent' ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	public function web2scan4cli4uniscan(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "uniscan -u '$this->http_type://$this->vhost:$this->port' -qwedsriogj ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}

	public function web2scan4cli4arachni(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		/*
		 * arachni_reporter --reporters-list
		 */
     // --http-proxy http://$this->proxy_addr:$this->proxy_port --report-save-path=$file_output.afr --scope-include-subdomains 
		// --plugin=proxy:port=8282,bind_address=127.0.0.1 --http-request-concurrency=8 
		$query = "arachni \"$this->http_type://$this->vhost:$this->port/\" --checks=* --audit-forms --audit-cookies --audit-links --audit-with-both-methods --audit-with-extra-parameter --audit-parameter-names --audit-headers --output-verbose  --audit-cookies-extensively --report-save-path=$this->dir_tmp ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function web2scan4cli4nikto(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    $query = "nikto -host '$this->http_type://$this->vhost' -port '$this->port' -timeout $this->stream_timeout -nointeractive -until 2400s -nolookup -maxtime 3600s -ask no -C all"; //-useragent '$this->user2agent' 
		
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function web2scan4cli4grabber(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$query = "grabber --url '$this->http_type://$this->vhost:$this->port' -s -x -b -z -d -i -j -c -e ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	
	
	public function web2scan4gui4w3af(){
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost","w3af_gui");
		$this->pause();
	}
	
	public function web2scan4gui4armitage(){
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost","armitage");$this->pause();
	}
	
	public function web2scan4gui4maltego(){
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost","maltego_ce");
		$this->pause();
	}

	public function web2scan4gui4msf(){
		$this->ssTitre(__FUNCTION__);
		$this->net("https://localhost:3790/" );$this->pause();
	}
	
	public function web2scan4gui4nessus(){
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S /etc/init.d/nessusd stop" );
		$this->cmd("localhost", "cd /opt/nessus/sbin/; echo '$this->root_passwd' | sudo -S ./nessuscli update" );
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S /etc/init.d/nessusd start" );
		$this->article ( "login/password", "root/toor" );
		$this->net("https://localhost:8834/nessus6.html" );	
		$this->pause();
	}
	
	public function web2scan4gui4nexpose(){
		$this->ssTitre(__FUNCTION__);
		$file = "/opt/rapid7/nexpose/nsc";
		if (!file_exists($file)) $this->install_nexpose();
		$this->cmd("localhost","cd $file; echo '$this->root_passwd' | sudo -S ./nsc.sh");
		$this->article("login/password", "nxadmin/nxpassword" ); 
		$this->net("http://localhost:3780/manager/html" );
		$this->pause();
	}

	public function web2scan4gui4burp(){
		//  cat zap.url.all | parallel -k "wget --spider -e use_proxy=yes -e http_proxy=127.0.0.1:$this->proxy_port_burp --no-verbose --no-check-certificate --user-agent='$this->user2agent' -e robots=off '{}'"
		$this->ssTitre(__FUNCTION__);
		while (!$this->tcp2open("127.0.0.1", $this->proxy_port_burp)) {
		$this->cmd("localhost","java -Djsse.enableSNIExtension=false -jar -Xmx1024m $this->dir_tools/web/burp/BurpLoader.jar");
		sleep(30);
		}
	}
	
	function web2response($reponse_http) {
		/*
		 *
		 * * net("www.ascii-table.com");
		 */
	
	
		$message = "";
		switch ($reponse_http) {
		    
		    case 100 :
		        $message = "Continue";
		        break;		        
		    case 101 :
		        $message = "Switching Protocols";
		        break;
	
		    case 200 :
		        $message = "OK";
		        break;
		   
		    case 201 :
		        $message = "Created";
		        break;
		        
		    case 202 :
		        $message = "Accepted";
		        break;
		        
		    case 203 :
		        $message = "Non-Authoritative Information";
		        break;
		        
		    case 204 :
		        $message = "No Content";
		        break;
		        
		    case 205 :
		        $message = "Reset Content";
		        break;
		        
		    case 206 :
		        $message = "Partial Content";
		        break;
		        
		    case 211 :
				$message = "Status du système ou réponse à la commande HELP";
				break;
			case 214 :
				$message = "Message d'aide";
				break;
			case 220 :
				$message = "Connexion etablie avec le serveur";
				break;
			case 221 :
				$message = "Connexion fermee par le serveur a la demande du client";
				break;
			case 250 :
				$message = "commande executee avec succes";
				break;
			case 251 :
				$message = "L'utilisateur n'est pas local";
				break;
			case 252 :
				$message = "User existant";
				break;
				
			case 300 :
			    $message = "Multiple Choices";
			    break;
			    
			case 301 :
			    $message = "Moved Permanently";
			    break;
			    
			case 302 :
			    $message = "Found";
			    break;
			    
			case 303 :
			    $message = "See Other";
			    break;
			    
			case 304 :
			    $message = "Not Modified";
			    break;
			    
			case 305 :
			    $message = "Use Proxy";
			    break;
			case 306 :
			    $message = "Unused";
			    break;
			    
			case 307 :
			    $message = "Temporary Redirect";
			    break;
			    
			case 354 :
				$message = "Commencer l'écriture du mail (finir avec un <CRLF>.<CRLF>";
				break;
			case 400 :
			    $message = "Bad Request";
			    break;
			case 401 :
			    $message = "Unauthorized";
			    break;
			case 402 :
			    $message = "Payment Required";
			    break;
			case 403 :
			    $message = "Forbidden";
			    break;
			case 404 :
			    $message = "Not Found";
			    break;
			case 405 :
			    $message = "Method Not Allowed";
			    break;
			case 406 :
			    $message = "Not Acceptable";
			    break;
			case 407 :
			    $message = "Proxy Authentication Required";
			    break;
			case 408 :
			    $message = "Request Timeout";
			    break;
			case 409 :
			    $message = "Conflict";
			    break;
			case 410 :
			    $message = "Gone";
			    break;
			case 411 :
			    $message = "Length Required";
			    break;
			case 412 :
			    $message = "Precondition Failed";
			    break;
			case 413 :
			    $message = "Request Entity Too Large";
			    break;
			case 414 :
			    $message = "Request-URI Too Long";
			    break;
			case 415 :
			    $message = "Unsupported Media Type";
			    break;
			case 416 :
			    $message = "Requested Range Not Satisfiable";
			    break;
			case 417 :
			    $message = "Expectation Failed";
			    break;
			    
			case 421 :
				$message = "Domaine non accessible";
				break;
			case 450 :
				$message = "Boite aux lettres inaccessible";
				break;
			case 451 :
				$message = "Action annulee : Erreur local dans le traitement de la demande";
				break;
			case 452 :
				$message = "Action non réalisée du à un problème de taille";
				break;
			case 500 :
				$message = "Internal Server Error - Erreur de syntaxe : commande non reconnue - Ligne trop longue.";
				break;
				// Erreur
				/*
		 * ,"500SQL" => "SQL Server Error"
		 * ,"500SQLP" => "SQL Server Perfect"
		 * ,"500SQLS" => "SQL Server Syntax"
		 * ,"500ACCESS" => "Access Driver"
		 * ,"500ADO" => "ADODB"
		 * ,"500JET" => "JET Database"
		 * ,"200XSS" => "Cross Site Scripting"
		 * ,"200FILE" => "File Upload Form"
				 */
			case 501 :
				$message = "Not Implemented - Erreur de syntaxe : parametres ou arguments inconnus - Chemin trop long	";
				break;
			case 502 :
				$message = "Bad Gateway - Commande non implémentée";
				break;
			case 503 :
				$message = "Service Unavailable - Mauvaise séquence de commandes";
				break;
			case 504 :
				$message = "Gateway Timeout - Paramètre de commande non implémenté";
				break;
			case 505 :
			    $message = "HTTP Version Not Supported";
			    break;
			case 550 :
				$message = "Action non réalisée : boite aux lettres inexistante";
				break;
			case 551 :
				$message = "Utilisateur inexistant";
				break;
			case 552 :
				$message = "Action annulee : probleme d'espace disque - Trop de récipiendaires - Message trop long";
				break;
			case 553 :
				$message = "Action non réalisée : boite aux lettres non trouvée ou interdite";
				break;
			case 554 :
				$message = "Envoi impossible";
				break;
			default :
				$message = "Code Inconnu $reponse_http";
				break;
		}
		return "$message\n";
	}
	

	public function web2waf(){
	    $result = "";
	    $this->titre(__FUNCTION__);
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->web2where AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->web2where"));
	    else {
	        
	    $result .= "wafw00f: ".$this->web2waf4wafw00f()."\n";
		$result .= "whatwaf: ".$this->web2waf4whatwaf()."\n";
		$result .= "nmap: ".$this->web2waf4nmap()."\n";
		
		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->web2where",$result));
	    }
	}
	
	
	
	public function web2waf4wafw00f(){
		$result = "";
		$result .= $this->ssTitre(__FUNCTION__);
		$query = "wafw00f -a -vvv $this->vhost ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	
	}
	public function web2waf4whatwaf(){
		$result = "";
		$result .= $this->ssTitre(__FUNCTION__);
		$query = "python whatwaf.py $this->vhost";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	public function web2waf4nmap(){
		$result = "";
		$result .= $this->ssTitre(__FUNCTION__);
		$query = "echo '$this->root_passwd' | sudo -S nmap --script=http-waf-fingerprint,http-waf-detect --script-args http-waf-fingerprint.intensive=1 $this->vhost -oX - ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	

	public function web2enum4php(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);

		$query = "nmap --script http-php-version -Pn -n $this->vhost -p \"http*\" | grep -i \"version\"  ";
		$result .= $this->cmd("localhost",$query);
		$result .= $this->req_ret_str($query);
		return $result;
	}
	
	
	public function web2scan4gui4arachni(){
		$this->ssTitre(__FUNCTION__);
		$this->article("login/pass","admin@admin.admin/administrator");
		$arachni_web = "/opt/arachni/bin/arachni_web";
		if (!file_exists($arachni_web)) $this->install_web2scan4gui4arachni();
		$this->net("http://localhost:9292/");
		$this->cmd("localhost", $arachni_web);
		$this->pause();
	}


	
	
	public function web2urls4spider(){
	    $tab_urls = array();
	    // https://api.hackertarget.com/pagelinks/?q=https://www.ubisoft.com/en-gb
	    $this->ssTitre(__FUNCTION__);// --proxy=http://$this->proxy_addr:$this->proxy_port  --output-dir=$this->rep_path -t $this->rep_path/$this->vhost.http.log.sqlmap --dump-format=SQLITE | tee $file_output 
		// webshag-cli
		$query = "hxwls '$this->web' 2> /dev/null | grep '$this->vhost' | grep -v '#' | sort -u ";
		$tab_urls = $this->req_ret_tab($query);
        $tab_urls = array_filter(array_unique($tab_urls));

        $this->article("URLs FROM SPIDERING", $this->tab($tab_urls));
        $this->pause();
		return $tab_urls;
	}
	
	public function web2enum(){
	    $result = "";
	    $this->titre(__FUNCTION__);
	    $sql_r_1 = "SELECT ".__FUNCTION__." FROM ".__CLASS__." WHERE $this->web2where AND ".__FUNCTION__." IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out(__FUNCTION__,__CLASS__,"$this->web2where"));
	    else {

	        $query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn --script=\"http-enum\" $this->vhost -p $this->port -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/ports/port/script/@output | strings "; // --script \"http-enum,http-title,http-traceroute,http-methods,http-headers,http-method-tamper\"
	        $result = $this->req_ret_str($query);
	    
		//$result .= $this->web2enum4user2agent(); // BUG USER AGENT 
		//$result .= $this->web2enum4dav(); // later 
		//$result .= $this->web2enum4bing();
		//$result .= $this->web2enum4google();
		

		$result = base64_encode($result);
		return base64_decode($this->req2BD4in(__FUNCTION__,__CLASS__,"$this->web2where",$result));
		 
	       }
	}
	
	
	public function web4info(){
	    $query = "echo '$this->root_passwd' | sudo -S nmap -n -Pn --script=\"http-title,http-traceroute,http-methods,http-headers,http-method-tamper\" $this->vhost -p $this->port -e $this->eth -oX - | xmlstarlet sel -t -v /nmaprun/host/ports/port/script/@output | strings "; // --script \"http-enum,http-title,http-traceroute,http-methods,http-headers,http-method-tamper\"
	    
	    
	    
	    return $this->req_ret_str($query);
	    
	}
	
	
	
}

?>