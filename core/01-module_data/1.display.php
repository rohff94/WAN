<?php


class com4display extends INSTALL {


    var $ftp_log_linux ;
    var $ssh_log_linux ;
    var $smtp_log_linux ;
    var $web_log_linux ;
    var $db_log_linux ;
    var $session_log_linux ;
    
    var $filter_file_path ;
    var $filter_host ;
    var $filter_ip ;
    var $filter_domain ;
    
    var $path_grep ;
    var $path_sort ;
    var $path_strings ;
    
   
    /*
     <td><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAptJREFUeNqkU01LVFEYfu7XzJ17nZmyJBW0sgRDRAgLoi8tghZG9QNaR7tg2vQjbCu2a9Eq2qRGUYFBZAtLURzSUUcJG8d0ZnTu99fpPdIMSktfOOfcezjP8z7vc94jMMZwmJD5JAhCfWPm0e2+MGKDYRQNBCHrpTWi/1kaExFjY7defp6qneXJhb3pHwGBH4qy8uSIrp9NqjJ0TXsXuvZ0KfvjacEVsIlEzhXkofuvJ0f+I+BgVdOftfZe0OIsQBBTFxLX7raxCIH75vn3xOjwQDbQsSgfNw0pkXkwPjXCsWJNNjFlmttPaWrqKBBTEb9yr0No7tCEptaU3H3xMgQJp90imo2C7plGZvhmbx/H7hHwmnUJnWpjI8L1ZSg7fyBoSQWUHo4FIabFwEJE5HeLX4JmVzqrtjdYN5GM6k95FlhpE4q5A8GzEWzkITYkKYWEqLgG+C58IgiIMx1WkfX0/joBud2Tsrco+wokZ5dAIsL5Scgnu8ACH/7qTyL14RDYo/NJZqPq+D37FYDtlqHlp6n+xF7WYHkO8ZBkE6G9tgQ3BCwabsTdBwzbw34P5oohfZaKwHYB2CrA+bWCyKwgyC/AIU+qnIDAAYE3PAmG48/tU8Am1uXU9XR1A4rrQ6S2iHwP9pe3dIc2/OouTCLgJfBYNCVYrj9RV8A7rCIncwvSMWz5JIDUyW2dkXr1DmKnzxFBuVwDZw0JMxXkLC8YqxPw9vSk2NC62mQui2mUA9rsvpSX0o1+vL2r7InxFzXwp03R/G1GQx9Na6pOwIO3p6U0ZFbjLbl56QRY9tsZbyU7W/jwalyKq4/fb6sYLSq5JUPIfA28kRruwFvgwTuMNwmNG3RV58ntkAyb5jVz2bXMB97CYeKvAAMACjWGjcO+NcIAAAAASUVORK5CYII="></td>

     */
    
    
	
	function __construct(){
		parent::__construct();	
		$this->filter_file_path = " | grep -i -Po \"(/[a-z0-9\-_\.]{1,})*\" | sort -u ";
		$this->filter_domain = " | grep -Po -i \"[0-9a-z\_\-]{1,}\.[a-z]{2,5}\"  | tr '[:upper:]' '[:lower:]' | grep -v -E \"(\.png$|\.js$|\.html$|\.css$|\.php$|\.xml$|\.asp$|\.jsp$|\.htm$|\.jpg$|\.jpeg$|\.gif$|\.ico$|this\.)\" | sort -u "; 
		$this->filter_host = " | grep -i -Po \"([0-9a-z\-\_\.]{0,})([0-9a-z\-\_]{1,})\.[a-z]{2,5}\" | tr '[:upper:]' '[:lower:]' | grep -v -E \"(\.png$|\.js$|\.html$|\.css$|\.php$|\.xml$|\.asp$|\.jsp$|\.htm$|\.jpg$|\.jpeg$|\.gif$|\.ico$|this\.)\" | sort -u ";
		$this->filter_ip = " | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | sort -u ";
		
	}

	function exec_para4print($cmd1, $cmd2, $time) {
	    $this->article("CMD1", $cmd1);
	    $this->article("CMD2", $cmd2);
	    
	    $cmd1 = base64_encode($cmd1);
	    $cmd2 = base64_encode($cmd2);
	    
	    $filename = "/tmp/exec_para";
	    if (!file_exists($filename)) $this->requette("gcc $this->dir_c/exec_para.c -o $filename");
	    //echo "$filename $cmd1 $cmd2 $time\n\n";
	    return "$filename $cmd1 $cmd2 $time";
	}
	
	function exec_parallel($cmd1, $cmd2, $time) {
	    $cmd1 = base64_encode($cmd1);
	    $cmd2 = base64_encode($cmd2);
	    
	    $filename = "/tmp/exec_para";
	    if (!file_exists($filename)) $this->requette("gcc $this->dir_c/exec_para.c -o $filename");
	    $this->requette("$filename $cmd1 $cmd2 $time");
	}
	
	
	
	
	public function log2succes($chaine){
	    
	    $this->notify($chaine);
	    $time = date("Y-m-d H:i:s");
	    $str = "$time,$chaine";
	    $str = addcslashes($str, "'");$str = addcslashes($str, "%");
	    $this->requette("echo '$str' >>  $this->log_succes_path");
	   
	}
	
	
	public function log2error($chaine){
	    $this->notify($chaine);
	    $time = date("Y-m-d H:i:s");
	    $str = "$time,$chaine";
	    $str = addcslashes($str, "'");
	    $this->requette("echo '$str' >>  $this->log_error_path");
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
	    $tmp = array_filter($tmp);
	    echo $this->tab($tmp);
	    //var_dump($tmp);
	    return $tmp;
	}
	
	public function stream2info($stream){
	    $this->article("Stream Type",get_resource_type($stream));
	    $this->article("Stream Meta DATA",$this->tab(stream_get_meta_data($stream)));
	    //var_dump(socket_get_option($stream));
	    //var_dump(stream_socket_get_name($stream,TRUE));
	    
	}
	public function stream4result($stream,$data,$timeout,$filter):array{
	    $result = "";
	    $tab_rst = array();
	    $data = trim($data);

	    
	    $this->article("Stream Type",get_resource_type($stream));
	    
	    $this->article("TIMEOUT", $timeout."s");
	    $this->article("DATA", $data);
	    $data = "echo '".base64_encode($data)."' | base64 -d | bash - "; // 2> /dev/null
	    $this->article("CMDLINE", $data);

	    if(is_resource($stream)){
	        
	        switch (get_resource_type($stream)){
	            // https://www.php.net/manual/fr/resource.php
	            
	            case "SSH2 Session":
	                $stream = ssh2_exec($stream, $data);
	                stream_set_blocking($stream, TRUE);
	                stream_set_timeout($stream, $timeout);
	                //
	                $result = $this->stream2norme($stream);
	                break;
	                
	                
	        case "stream" :	 

	            
	            fflush($stream);
	            //var_dump($this->stream);
	            fputs($stream, "$data\n");
	            fflush($stream);
	            stream_set_blocking($stream, TRUE);
	            stream_set_timeout($stream,$timeout);
	            $result = $this->stream2norme($stream);
	            break;
	            
	        case "Unknown":
	            $this->log2error("unknown stream");
	            break;
	            
	        default:
	            $this->log2error("unknown default stream");
	            break;
	            
	        }
	        
	    }
	    
	    $command = "echo '$result' $filter ";
	    exec($command,$tab_rst);
	    return $tab_rst;
	}
	
	public function stream2norme($stream){
	    $this->ssTitre(__FUNCTION__);
	    fgets($stream);
	    $result = "";
	    $result = @stream_get_contents($stream);

	    
	    $tmp = explode("\n", $result);
	    array_pop($tmp);
	    $result = $this->tab($tmp);
	    
	    echo $result."\n";
	    return $result;
	}
	
	public function req_str($stream,$data,$timeout,$filter){
	    if (is_resource($stream)) return $this->chaine($this->stream4result($stream, $data, $timeout,$filter));
	    else return $this->req_ret_str("$data $filter");	    
	    }
	
	    
	    public function req_tab($stream,$data,$timeout,$filter):array{
	        if (is_resource($stream)) return $this->stream4result($stream, $data, $timeout,$filter);
	        else return $this->req_ret_tab("$data $filter");
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
	
		public function str2file($stream,$str,$file_path){
		    if (empty($stream))   file_put_contents($file_path, $str);
		    else {
		        $input = addcslashes($str, "'");
		        $data = "echo '$input' >  $file_path";
		        $this->req_str($stream, $data, $this->stream_timeout, "");
		    }
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