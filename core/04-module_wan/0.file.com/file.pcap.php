<?php
class PCAP extends FILE {



	public  function __construct($pcap) {
	    parent::__construct($pcap);
	}
	

	public function file_pcap2for(){
		$this->ssTitre(__FUNCTION__);
		// svn checkout http://tstat.polito.it/svn/software/tstat/trunk tstat
		// http://www.netresec.com/?page=PcapFiles
	
		$this->file_pcap2dot();$this->pause();
		$this->file_pcap2info();$this->pause();
		$this->file_pcap2tcptrace();$this->pause();
		$this->file_pcap2content();$this->pause();
		//$this->file_pcap2tcptrack();$this->pause();
		$this->file_pcap2ssldump();$this->pause();
		$this->file_pcap2tcpdump();$this->pause();
		$this->file_pcap2driftnet();$this->pause();
		$this->file_pcap2arpwatch();$this->pause();
		$this->file_pcap2tshark();$this->pause();
		$this->file_pcap2snort();$this->pause();
		$this->file_pcap2ngrep();$this->pause();
		
	

	
		//pause();
		//todo("ruby $this->dir_tools/for/macfinder.rb -i 192.168.1.10 $this->file_path");
		//todo("ruby $this->dir_tools/for/httpdumper.rb -r $this->file_path --stats request,192.168.1.10");
		//todo("ruby $this->dir_tools/for/httpdumper.rb -r $this->file_path --stats uri,192.168.1.10,ax.search.itunes.apple.com");
		//$this->requette("ruby $this->dir_tools/for/httpdumper.rb -r $this->file_path -c 2");//pause();
		//todo("ruby $this->dir_tools/for/httpdumper.rb -r $this->file_path --stats uri,192.168.1.10");
		//$this->requette("ruby $this->dir_tools/for/httpdumper.rb -r $this->file_path -c 5");//pause();
		//$this->requette("ruby $this->dir_tools/for/httpdumper.rb -r $this->file_path -c 5 -f 1 -d");//pause();
		//file2file($this->file_path,"$rep_path/$vmem_name.bulk/pcap/");
	
		//if (!file_exists("/etc/init.d/xplico")) $this->install_for_xplico();
		//$this->cmd("localhost"," /etc/init.d/xplico start");
		//net("http://localhost:9876"); // xplico/xplico
	
		//file2yara($this->file_path,$yara_file);//pause();
	
	
		$this->file_pcap2dot();$this->pause();
	}
	
	public function file_pcap4eth($eth, $time_seconde) {
		$this->ssTitre("Capture Traffic from $eth" );
		// tshark -i wlan0 -T fields -e frame.number -e ip.src -e ip.dst -e frame.len -e frame.time -e frame.time_relative -E header=y -E separator=,
		// -T fields -E separator=, -E quote=d
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S tshark -i $eth -a duration:$time_seconde $filter -w $this->file_dir/$eth.pcap" );
		return "$this->file_dir/$eth.pcap";
	}
	
	
	public function file_pcap2csv($filter_colon) {
		$this->ssTitre("Convert PCAP to CSV" );
		$this->requette("echo '$this->root_passwd' | sudo -S tshark -r $this->file_path -T fields $filter_colon -E separator=, -w $this->dir_tmp/pcap2csv.csv " );
	}
	
	public function file_pcap2ngrep(){
	    $this->ssTitre(__FUNCTION__);
	    $file_output = "$this->file_path.".__FUNCTION__;
	    $query = "ngrep -I $this->file_path | tee $file_output ";

	    
	    $query = "ngrep -i 'USER|PASS' -I $this->file_path  | tee $this->file_path.ngrep2usr";
	    $this->requette($query);
	    $this->pause();
	    
	    $query = "ngrep -i 'http://' -I $this->file_path | tee $this->file_path.ngrep2url";
	    $this->requette($query);
	    $this->pause();
	    
	    if (!file_exists($file_output)) $this->requette($query); else $this->cmd("localhost",$query);//pause();
	    return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	public function file_pcap2info(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "capinfos $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	public function file_pcap2tcptrace(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "tcptrace $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	public function file_pcap2content(){
	    $this->ssTitre(__FUNCTION__);
	    $file_output = "$this->file_path.".__FUNCTION__;
	    $query = "tcpdump -X -r $this->file_path | tee $file_output";
	    if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
	    return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	public function file_pcap2tcptrack(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		return ; // pas la peine -> pas de retour au terminal 
		$query = "tcptrack -T $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	public function file_pcap2ssldump(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "ssldump -r $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	public function file_pcap2tcpdump(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "tcpdump -r $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	public function file_pcap2driftnet(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "driftnet -f $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	public function file_pcap2arpwatch(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "arpwatch -r $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	public function file_pcap2tshark(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "tshark -r $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	public function file_pcap2gui4xplico(){
		$this->ssTitre(__FUNCTION__);
		if (! file_exists ( "/etc/init.d/xplico" )) $this->install_for_xplico ();
		$this->cmd( "localhost", "echo '$this->root_passwd' | sudo -S /etc/init.d/xplico start" );
		$this->net ( "http://localhost:9876" ); // xplico/xplico
	}
	
	
	
	public function file_pcap2dot(){
		$this->file_pcap2dot4ip();
		$this->file_pcap2dot4ip2host();
		$this->file_pcap2dot4ip2ver();
		$this->file_pcap2dot4http2user();
		$this->file_pcap2dot4http2referer();
		$this->file_pcap2dot4proto();
		$this->file_pcap2dot4url();
		$this->file_pcap2dot4dns();
		$this->file_pcap2dot4server();
		/*
		$IPs = explode("\n", $this->file_pcap2ip());
		foreach ($IPs as $ip)
			if (!empty($ip)){
				$obj_ip = new IP($ip);
				$obj_ip->ip2for();
		}
		$this->ip2dot4all($this->file_dir,"PCAP:$this->file_dir FOR ");
		*/
	}
	
	public function file_pcap2dot4ip2host(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e ip.src -e ip.dst_host -e tcp.dstport | grep -v \"^,\" | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	public function file_pcap2dot4ip2ver(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e ip.src -e ip.dst -e ip.version | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	public function file_pcap2dot4http2user(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e http.host -e http.server -e http.user2agent | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	public function file_pcap2dot4http2referer(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e -e http.host -e http.server -e http.referer | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	
	public function file_pcap2dot4ip(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e ip.src -e ip.dst -e tcp.dstport | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	public function file_pcap2dot4layer2(){
	    $this->ssTitre(__FUNCTION__);
	    //$file_output = "$this->file_path.".__FUNCTION__.".dot";
	    $filename = "/opt/PcapViz/main.py";
	    if (!file_exists($filename)) $this->install_dot_pcapviz();
	    $this->requette("python3 $filename -i $this->file_path -o $this->file_dir/$this->file_name.png -g dot --layer2 ");
	    //$this->requette("gedit $file_output");$this->dot2xdot($file_output);
	}
	
	
	public function file_pcap2dot4proto(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e ip.src -e ip.dst -e ip.proto | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	public function file_pcap2dot4url(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e ip.src -e http.host -e http.request.uri  | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	
	public function file_pcap2dot4dns(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e ip.src -e dns.qry.name -e dns.resp.addr | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	public function file_pcap2dot4server(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__.".dot";
		$this->requette("tshark -r $this->file_path -T fields -E separator=, -e ip.src -e http.host | sort -u  | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $file_output ");
		$this->requette("gedit $file_output");
		$this->dot2xdot($file_output);
	}
	
	
	
	public function file_pcap2snort(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "echo '$this->root_passwd' | sudo -S snort -v -A console -c /etc/snort/snort.conf -r $this->file_path | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	
	public function file_pcap2file($file_input,$rep_output){
		if(!file_exists("$rep_output/audit.txt"))	$this->requette("foremost -i $file_input -t all -v  -o $rep_output -w ");
	}
	
	
	public function file_pcap2ip(){
		$this->ssTitre(__FUNCTION__);
		$file_output = "$this->file_path.".__FUNCTION__;
		$query = "tshark -nn -r $this->file_path -T fields -e ip.dst | tee $file_output";
		if (file_exists($file_output)) $this->cmd("localhost","$query");else return $this->req_ret_str($query);
		return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	
}



?>