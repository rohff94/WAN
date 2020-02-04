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
	public function __construct($bin) {
	parent::__construct($bin);
	//$this->ssTitre("avoid creating cores on crashes (speed-up)");$this->requette("echo '$this->root_passwd' | sudo -S /etc/init.d/apport stop"); 

	}
	


	function offset2eip($eip_val, $size) {
		$eip_val = trim($eip_val); $size = trim($size);
		$win_offset_eip = $this->req_ret_str( "python $this->dir_tools/bof/pattern.py offset $eip_val $size" );
		$this->article("Offset EIP", $win_offset_eip );
		return $win_offset_eip;
	}
	

	
	public function code2file($c_code) {
		$this->ssTitre(__FUNCTION__);
		$fp = fopen("$this->file_path.sc", 'w+');
		fputs($fp,$c_code);
		fclose($fp);
		return "$this->file_path.sc";
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