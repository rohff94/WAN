<?php


class URL extends WEB{
    var $url;
    var $uri_path;
    var $uri_dirname_path;
    var $uri_query ;
    var $meta_tags ;

	

    
	public function __construct($stream,$url) {	
	    $this->url = trim($url);
	    if (empty($this->url)) return $this->log2error("EMPTY URL");
	    parent::__construct($stream,$url);		
	    $this->uri_path = parse_url( $this->url, PHP_URL_PATH);
	    $this->uri_path_dirname = dirname($this->url);
	    $this->uri_query = parse_url( $this->url, PHP_URL_QUERY);
	    $this->article("URL", $this->url);

	}


	
	public function url2scan(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
	    $query = "commix --batch --url='$this->url' --level=3 2>&1 ";
	    $result .= $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	
	
	public function url4pentest(){

	    $this->gtitre(__FUNCTION__);
	    $my_arr = array();
        $this->url2spider();
        //$result .= $this->url2scan(); //takes too long time
        
        $OS = $this->ip2os4arch($this->ip2os());
		parse_str(parse_url( $this->url, PHP_URL_QUERY),$my_arr);
		foreach($my_arr as $key=>$value){	
			if(!is_array($key && !empty($value))){
			    
			    $obj_fi = new PARAM($this->eth,$this->domain,$this->url,$key,$value,"GET");
			    $obj_fi->poc($this->flag_poc);
				$obj_fi->param4pentest($OS);
				$this->pause();
		}
					}

		
	}
	

	
	
	public function url2spider(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    $code = "";
	    $result = "";
	    if (!empty($this->url)){
	        
	        /*
	        $this->web2scan4gui4burp();
	        $this->article("Burp","localproxy $this->proxy_port_burp ");
	        $this->requette("wget -qO- --no-check-certificate --timeout=2 --tries=1 -e use_proxy=yes -e http_proxy=$this->proxy_addr:$this->proxy_port_burp -e https_proxy=$this->proxy_addr:$this->proxy_port_burp \"$this->url\" --user-agent='$this->user2agent' > /dev/null ");
	        $this->web2scan4gui4zap();
	        */
	        
	        $code = $this->url2code($this->url);
	        $code = trim($code);
	        $this->web2response($code);
	        switch ($code) {
	            case "401" :
	                $this->auth2login4hydra($this->req_ret_str("hydra -l \"admin\" -P $this->dico_users.small $this->ip http-get -s $this->port '$this->uri_path' -w 5s 2>/dev/null | grep -i  'login:' "));
	                $this->auth2login4hydra($this->req_ret_str("hydra -l \"guest\" -P $this->dico_users.small $this->ip http-get -s $this->port '$this->uri_path' -w 5s 2>/dev/null | grep -i  'login:' "));
	                $this->auth2login4hydra($this->req_ret_str("hydra -l \"administrator\" -P $this->dico_users.small $this->ip http-get -s $this->port '$this->uri_path' -w 5s 2>/dev/null | grep -i  'login:' "));
	                $this->auth2login4hydra($this->req_ret_str("hydra -l \"user\" -P $this->dico_users.small $this->ip http-get -s $this->port '$this->uri_path' -w 5s 2>/dev/null | grep -i  'login:' "));
	                $this->auth2login4hydra($this->req_ret_str("hydra -l \"test\" -P $this->dico_users.small $this->ip http-get -s $this->port '$this->uri_path' -w 5s 2>/dev/null | grep -i  'login:' "));
	               $tab_users=$this->ip2users4shell();
	               if(!empty($tab_users)){
	                   foreach ($tab_users as $user){
	                       $user = trim($user);
	                    if (!empty($user)) $this->auth2login4hydra($this->req_ret_str("hydra -l '$user' -P $this->dico_users.small $this->ip http-get -s $this->port '$this->uri_path' -w 5s 2>/dev/null | grep -i  'login:' "));	                       
	                   }
	               }
	                break;
	            case "200" :
	                $result .= $this->url2ok();
	                break;
	        }
	    }
	    return $result;
	}
	
	
	public function url2ok(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    $result .= $this->url2form($this->url);
	    $result .= $this->url2info();
	    //$result .= $this->url2html("", $this->url2wget("", "", $this->url, "GET"));
	    return $result;
	}

	public function url2xml(){
	    $this->ssTitre(__FUNCTION__);
	    $sha1url = sha1($this->url);
	    $filexml_path = "$this->dir_tmp/$sha1url.xml";
	    $query = "echo \"<?xml version='1.0' encoding='UTF-8'?>\" > $filexml_path";
	    $this->requette($query);
	    $query = "hxnormalize -e '$this->url' >> $filexml_path";
        $this->requette($query);
        $query = "cat $filexml_path | xmlstarlet  sel -t -v";
        $this->requette($query);
        $this->requette("gedit $filexml_path");
        return $filexml_path;
	}

	public function url2info(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "wget --user-agent='$this->user2agent' '$this->url' --timeout=2 --tries=2 --no-check-certificate -qO- 2>&1 | grep -Po \"(10.|192.168|172.1[6-9].|172.2[0-9].|172.3[01].).*\" | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | sort -u";
	    $result = $this->cmd("localhost",$query);
	    $result .= $this->req_ret_str($query);
	    return $result;
	}
	
	
	public function url2dot4all(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->url_rep_path.".__FUNCTION__;
	}
	
	
	public function url2screenshot(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$file_output = "$this->url_rep_path.".__FUNCTION__.".png";
		$query = "cutycapt --url=$this->url --out=$file_output ";
		if (file_exists($file_output)) $this->cmd("localhost", $query);else $this->requette($query);
		$this->img($file_output);
	}
	

	
	
	public function url2cookies($url){
	    $this->ssTitre(__FUNCTION__);
	    //
	    $query = "wget --user-agent='$this->user2agent' --server-response --spider --keep-session-cookies \"$url\" -qO-  ";
	    $this->requette($query);
	    $query = "curl --silent --output /dev/null --connect-timeout 10 --no-keepalive --head \"$url\" | grep -i 'Set-Cookie' | cut -d'=' -f2 | cut -d';' -f1 | grep -Po \"[a-z0-9]{32,}\"  ";
	    
	    return $this->req_ret_str($query);
	}
	
	public function url2form($url){
	    $this->ssTitre(__FUNCTION__); // --proxy=http://$this->proxy_addr:$this->proxy_port  --output-dir=$this->rep_path -t $this->rep_path/$this->vhost.http.log.sqlmap --dump-format=SQLITE | tee $file_output
	    $query = "wget --user-agent='$this->user2agent' \"$url\" --timeout=2 --tries=2 --no-check-certificate -qO- 2> /dev/null   | perl $this->dir_tools/web/formfind.pl ";
	    return $this->req_ret_str($query);
	}
	
	public function url2encode($chaine){
	    $uri_encoded = "";
	    for($i = 0; $i < strlen($chaine)-1; $i ++)
	        $uri_encoded .= "%" . dechex(ord($chaine [$i]));
	        return $uri_encoded ;
	}
	
	
	


	
	

	

	
	public function url2dot(){
	    $result = "";
	    $result .= $this->ssTitre(__FUNCTION__);
		$dir_img = "./IMG";
		$url2dot_ns = "";
		$url2dot_vhost = "";
		$url2dot_edge = "";
		$url2dot4body = "";
			
		$file_output = "$this->url_rep_path.".__FUNCTION__.".dot";
		$color_dns = "steelblue";$color_host = "steelblue";$color_url = "steelblue";$color_arrow = "steelblue";
		$url2dot_header = "digraph structs {
	label = \"".__FUNCTION__.":$this->vhost\";
			graph [rankdir = \"LR\" layout = dot];
			node [fontsize = \"16\" shape = \"plaintext\"];
			edge [penwidth=2.0 ];";
			$url2dot_vhost .= "
			\"$this->url\" [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">
		<TR><TD>URI</TD><TD PORT=\"uri\" bgcolor=\"$color_url\">$this->uri_path</TD></TR>
		<TR><TD>HASH</TD><TD PORT=\"param2hash\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->param2hash()))."</TD></TR>
		<TR><TD>CODE</TD><TD PORT=\"url2code\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->uri_path2code()))."</TD></TR>
		<TR><TD>HEADER</TD><TD PORT=\"url2header\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->uri_path2header()))."</TD></TR>
		<TR><TD>METHODS</TD><TD PORT=\"url2methods\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->uri_path2methods()))."</TD></TR>
		<TR><TD>COOKIES</TD><TD PORT=\"url2cookies\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->uri_path2cookies()))."</TD></TR>
		<TR><TD>SHELLSHOCK</TD><TD PORT=\"url2shellshock\" >".$this->dot2diagram(str_replace("\n","<BR/>\n",$this->uri_path2shellshock()))."</TD></TR>
		</TABLE>>];
				";
		$url2dot_footer = "
		}";
		
		$url2dot = $url2dot_header.$url2dot_vhost.$url2dot_edge.$url2dot_footer;
				$url2dot4body = $url2dot_vhost;
				system("echo '$url2dot' > $file_output ");
				//$this->requette("gedit $file_output");$this->dot2xdot("$file_output ");
				$this->dot4make($file_output,$url2dot);
				return $url2dot4body;
	}
	





	
	public function url2check($user2agent,$url,$filter){
	    $this->ssTitre(__FUNCTION__);
	    if (empty($this->url2html("", $this->url2wget("", "", $url, "GET")))) return FALSE ;
	    else return TRUE;
	}
	
	
	public function url2add4www($url){
	    $vhost = parse_url($url, PHP_URL_HOST) ;
	    if ($this->isDomain($vhost)) $url = "www.$vhost";
	    else return $vhost;
	    return $url;
	}
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
?>