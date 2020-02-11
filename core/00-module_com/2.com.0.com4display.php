<?php


class com4display extends INSTALL {


    var $ftp_log_linux ;
    var $ssh_log_linux ;
    var $smtp_log_linux ;
    var $web_log_linux ;
    var $db_log_linux ;
    var $session_log_linux ;
    
    var $filter_file_path ;
    var $path_grep ;
    var $path_sort ;
    var $path_strings ;
    
    
	
	function __construct(){
		parent::__construct();	
		$this->filter_file_path = " | grep -i -Po \"(/[a-z0-9\-\_\.]{1,})*\"";
	}

	

	
	//  jaune gras | jaune
	public function cmd($host,$query){
	    $query = str_replace("echo '$this->root_passwd' | sudo -S", "sudo", $query);
	    $display_cli = "\t\033[37;41;1;1mHost:\033[0m\033[37;40;1;4m$host:$:\033[0m \033[33;40;1;1m$query\033[0m\n";
	    $display_xml = "<host>$host</host><query>$query</query>\n";
	    echo  $display_cli;
	    return $display_xml;
	}
	
	
	public function req_ret_tab($chaine){
	    $tmp = array();
	    
	    $display = str_replace("echo '$this->root_passwd' | sudo -S", "sudo", $chaine);
	    if (empty($chaine)) return $tmp;
	    echo  "\t\033[33;40;1;1m$display\033[0m\n";
	    exec($chaine,$tmp);
	    //$resu = trim($tmp[0]);unset($tmp);
	    if (empty($tmp)) {$this->note("Empty Result");return $tmp;}
	    echo $this->tab($tmp);
	    return array_filter($tmp);
	}
	
	public function req_str($stream,$data,$timeout){
	    if (empty($data)) return "";

	    if(!is_resource($stream)) return $this->req_ret_str($data);
	    
	    $result = "";
	    $stdin = posix_ttyname(STDIN);
	    $stdout = posix_ttyname(STDOUT);
	    $stderr = posix_ttyname(STDERR);
	    
	    var_dump($stdin);
	    var_dump($stdout);
	    var_dump($stderr);
	    
	    //echo "\n";
	    $this->article("Stream Type",get_resource_type($stream));

	    $this->article("CMD", $data);
	    $this->article("TIMEOUT", $timeout);
	    $data = "echo '".base64_encode($data)."' | base64 -d | sh - ";
	    
	    if(is_resource($stream)){
	        
	        switch (get_resource_type($stream)){
	            
	            case "SSH2 Session":
	                $stream_ssh = ssh2_exec($stream, $data);
	                //$stream = ssh2_shell($con, 'vt102', null, 80, 24, SSH2_TERM_UNIT_CHARS);
	                //$stream_out = ssh2_fetch_stream($stream, SSH2_STREAM_STDIO);
	                // OK
	                $tmp = '';
	                stream_set_timeout($stream_ssh, $timeout);
	                stream_set_blocking($stream_ssh, TRUE);
	                
	                $info = stream_get_meta_data($stream_ssh);
	                var_dump($info);
	                $tmp = stream_get_contents($stream_ssh);
	                echo $tmp;
	                $result .= $tmp ;
	                //$result .= $this->article("CMD", $data); $this->pause();
	                //  }
	                break;
	                
	                
	        case "stream" :
	            
	            fflush($stream);
	            //var_dump($stream);
	            fputs($stream, "$data\n");
	            stream_set_timeout($stream,$timeout);
	            stream_set_blocking($stream, TRUE);
	            
	            $info = stream_get_meta_data($stream);
	            //var_dump($info);
	            
	            //sleep(1);
	            $result = stream_get_contents($stream);
	            echo $result;
	            break;
	            
	        case "Unknown":
	            $this->rouge("unknown stream");
	            break;
	            
	        case "process":
	            $this->rouge("Process stream");
	            $stream_o = popen($stream, "w");
	            var_dump($stream);
	            fwrite($stream_o, "$data\n");
	            stream_set_timeout($stream_o,$timeout);
	            stream_set_blocking($stream_o, TRUE);
	            
	            $info = stream_get_meta_data($stream_o);
	            var_dump($info);
	            
	            //sleep(1);
	            $result = stream_get_contents($stream_o);
	            echo $result;
	            break;
	            $descriptorspec = array(
	                0 => array("pipe", "r"),  // // stdin est un pipe où le processus va lire
	                1 => array("pipe", "w"),  // stdout est un pipe où le processus va écrire
	                2 => array("file", "/tmp/error-output.txt", "a") // stderr est un fichier
	            );
	            
	            $cwd = '.';
	            $env = array('quelques_options' => '-i');
	            
	            $process = proc_open('/bin/sh', $descriptorspec, $pipes, $cwd, $env);
	            
	            if (is_resource($process)) {
	                // $pipes ressemble à :
	                // 0 => fichier accessible en écriture, connecté à l'entrée standard du processus fils
	                // 1 => fichier accessible en lecture, connecté à la sortie standard du processus fils
	                // Toute erreur sera ajoutée au fichier /tmp/error-output.txt
	                
	                fwrite($pipes[0], 'ls -al');
	                fclose($pipes[0]);
	                
	                echo stream_get_contents($pipes[1]);
	                fclose($pipes[1]);
	                
	                // Il est important que vous fermiez les pipes avant d'appeler
	                // proc_close afin d'éviter un verrouillage.
	                //$return_value = proc_close($process);
	                
	                echo "La commande a retourné $return_value\n";
	            }
	            break;
	            
	            
	    }
	    
	}
	
	return $result;
	
	}
	
	
	public function req_ret_str($query){
	    $tmp = array();
	    if (empty($query)) return "";
	    $display = str_replace("echo '$this->root_passwd' | sudo -S", "sudo", $query);
	    if (empty($query)) return "";
	    echo  "\t\033[33;40;1;1m$display\033[0m\n";
	    exec($query,$tmp);
	    //$resu = trim($tmp[0]);unset($tmp);
	    if (empty($tmp)) return $this->note("Empty Result");
	    echo $this->tab($tmp);
	    return $this->tab($tmp);
	    //return trim($tmp[0]);
	}
	
	// jaune gras
	public function requette($query){
	    $display = str_replace("echo '$this->root_passwd' | sudo -S", "sudo", $query);
	    if (empty($query)) return "";
	    echo  "\t\033[33;40;1;1m$display\033[0m\n";
	    system($query);
	}


		public function tab2file($tab,$file_path){
		$fp = fopen($file_path, 'w+');
		foreach ($tab as $val)
		fputs($fp,"$val\n");
		fclose($fp);
		return file($file_path);
		}
	
		public function str2file($str,$file_path){
		    file_put_contents($file_path, $str);
		}



		// =============== WITHOUT PROTECTION ASLR =================
		function os2aslr4no() {
			// disable ASLR as follows:
			// #echo "0" > /proc/sys/kernel/randomize_va_space
			// #echo "0" > /proc/sys/kernel/exec-shield
			// #echo "0" > /proc/sys/kernel/exec-shield-randomize
			$this->ssTitre("NO PROTECTION ASLR");
			$this->article("ESP SANS random", "Check if cat /proc/sys/kernel/randomize_va_space 0 = 0");
			$query = "echo '$this->root_passwd' | sudo -S php -r \"system('echo 0 > /proc/sys/kernel/randomize_va_space');\";";
			$this->requette($query);
			
			$this->ssTitre("check if Randomisation ASLR is Disable");
		
			$this->os2aslr4check();
		}
		// =========================================================
		
		// =============== WITH ASLR PROTECTION =================
		function os2aslr4yes() {
			$this->titre("WITH PROTECTION ASLR");
			echo "ESP WITH random :\nCeck if cat /proc/sys/kernel/randomize_va_space 1 = 1\n";
			$query = "echo '$this->root_passwd' | sudo -S php -r \"system('echo 1 > /proc/sys/kernel/randomize_va_space');\";";
			$this->requette($query);$this->ssTitre("check if Randomisation ASLR is enable");
			$this->os2aslr4check();
		}
		// =========================================================
		
		public function os2aslr4check(){
		    $file_path = "$this->dir_tmp/find_esp.elf";
		    if (! file_exists($file_path)) {
		        system("cp -v $this->dir_c/find_esp.c $this->dir_tmp/find_esp.c");
		        $bin = new file("$this->dir_tmp/find_esp.c");
		        $file_path = $bin->file_c2elf("-m32 -w");
		    }
		    system("for i in `seq 10`; do $file_path; done && echo ");
		    system("for i in `seq 3`; do ldd $file_path | grep 'linux-gate.so' ; done && echo ");
		}

		
		

	
	
	
	
	

	
		// ##################################################################################################

	
	
	
	
}

?>